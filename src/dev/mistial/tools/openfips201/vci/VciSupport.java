/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.vci;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Host-side helpers for the PIV VCI (secure messaging, OPACITY ZKM CS2) flow used by the VCI tool.
 *
 * <p>This deliberately mirrors the byte-level contract implemented by the applet
 * ({@code PIV.generalAuthenticateCase1A} / {@code PIVSecureMessaging}) and by the OpenPhysical .NET
 * stack ({@code PivSecureMessagingBootstrapper} / {@code PivSecureMessagingProvider}). It only
 * supports Cipher Suite 2 (ECC P-256, AES-128, SHA-256), which is what the applet advertises.
 *
 * <p>The CVC profile is the cross-repo contract documented in the VCI plan: a {@code 7F21} card
 * verifiable certificate carrying the card SM public key in {@code 7F49/86} and an ECDSA-SHA256
 * signature in {@code 5F37} over all preceding bytes of the {@code 7F21} value.
 */
final class VciSupport {

  static final byte ALG_CS2 = (byte) 0x27;
  static final byte KEY_REF_SECURE_MESSAGING = (byte) 0x04;

  // CVC tags (SP 800-73-4-shaped).
  static final int TAG_CVC = 0x7F21;
  static final int TAG_CVC_PROFILE = 0x5F29;
  static final int TAG_CVC_ISSUER_ID = 0x42;
  static final int TAG_CVC_SUBJECT_ID = 0x5F20;
  static final int TAG_CVC_PUBLIC_KEY = 0x7F49;
  static final int TAG_CVC_PUBLIC_KEY_OID = 0x06;
  static final int TAG_CVC_PUBLIC_POINT = 0x86;
  static final int TAG_CVC_ROLE = 0x5F4C;
  static final int TAG_CVC_SIGNATURE = 0x5F37;
  static final byte CVC_PROFILE_IDENTIFIER = (byte) 0x80;

  // Role byte per the secure-messaging CVC profile, matching production PIV cards (0x00).
  static final byte CVC_ROLE_KEY_ESTABLISHMENT = (byte) 0x00;

  // Named-curve OID content placed in the 7F49 public-key template (tag 06), as production cards do.
  // CS2 uses prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
  private static final byte[] CURVE_OID_P256 = {
    0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07
  };

  private static final byte[] KEY_CONFIRMATION_CONTEXT = {0x4B, 0x43, 0x5F, 0x31, 0x5F, 0x56};
  private static final int COORD_LENGTH = 32;
  private static final int KEY_LENGTH = 16;

  private VciSupport() {}

  // ---------------------------------------------------------------------------------------------
  // CVC build / verify
  // ---------------------------------------------------------------------------------------------

  /**
   * Builds the body (the value of the outer {@code 7F21}) preceding the signature, for the card SM
   * public key.
   */
  static byte[] buildCvcBody(byte[] cardPublicPoint, byte[] issuerId, byte[] subjectId) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    writeTlv(body, TAG_CVC_PROFILE, new byte[] {CVC_PROFILE_IDENTIFIER});
    writeTlv(body, TAG_CVC_ISSUER_ID, issuerId);
    writeTlv(body, TAG_CVC_SUBJECT_ID, subjectId);
    // 7F49 public-key template: named-curve OID (tag 06) followed by the uncompressed point
    // (tag 86), matching the encoding production PIV cards present.
    ByteArrayOutputStream keyTemplate = new ByteArrayOutputStream();
    writeTlv(keyTemplate, TAG_CVC_PUBLIC_KEY_OID, CURVE_OID_P256);
    writeTlv(keyTemplate, TAG_CVC_PUBLIC_POINT, cardPublicPoint);
    writeTlv(body, TAG_CVC_PUBLIC_KEY, keyTemplate.toByteArray());
    writeTlv(body, TAG_CVC_ROLE, new byte[] {CVC_ROLE_KEY_ESTABLISHMENT});
    return body.toByteArray();
  }

  /**
   * Assembles the complete CVC ({@code 7F21}) from its signed body and the raw DER ECDSA-Sig-Value.
   * The {@code 5F37} signature is encoded as an X.509 SignatureValue
   * (SEQUENCE&#123; AlgorithmIdentifier(ecdsa-with-SHA256), BIT STRING&#123;ECDSA-Sig-Value&#125; &#125;),
   * the format production PIV cards present and that SP 800-73-5 relying parties expect.
   */
  static byte[] assembleCvc(byte[] cvcBody, byte[] ecdsaSigValueDer) {
    try {
      ByteArrayOutputStream value = new ByteArrayOutputStream();
      value.write(cvcBody, 0, cvcBody.length);

      ASN1EncodableVector algorithmId = new ASN1EncodableVector();
      algorithmId.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
      ASN1EncodableVector signatureValue = new ASN1EncodableVector();
      signatureValue.add(new DERSequence(algorithmId));
      signatureValue.add(new DERBitString(ecdsaSigValueDer));
      byte[] wrapped = new DERSequence(signatureValue).getEncoded("DER");

      byte[] sigTlv = tlv(TAG_CVC_SIGNATURE, wrapped);
      value.write(sigTlv, 0, sigTlv.length);
      return tlv(TAG_CVC, value.toByteArray());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to assemble CVC signature value", e);
    }
  }

  /**
   * Verifies a card CVC against the signer public key per the documented profile: the trailing
   * {@code 5F37} signature must verify (ECDSA-SHA256) over all bytes of the {@code 7F21} value that
   * precede it.
   *
   * @return true if the signature is present and valid.
   */
  static boolean verifyCvc(byte[] cvc, PublicKey signerPublicKey) {
    try {
      int[] outer = locateTlv(cvc, 0, TAG_CVC);
      if (outer == null) {
        return false;
      }
      int valueOffset = outer[1];
      int valueLength = outer[2];

      int[] signature = locateTlv(cvc, valueOffset, TAG_CVC_SIGNATURE);
      if (signature == null) {
        return false;
      }
      int signatureTagOffset = signature[0];
      // The signature must be the final element of the body.
      if (signature[1] + signature[2] != valueOffset + valueLength) {
        return false;
      }

      int signedLength = signatureTagOffset - valueOffset;
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(signerPublicKey);
      verifier.update(cvc, valueOffset, signedLength);
      byte[] signatureField = Arrays.copyOfRange(cvc, signature[1], signature[1] + signature[2]);
      return verifier.verify(unwrapCvcSignature(signatureField));
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Returns the raw ECDSA-Sig-Value (DER {@code SEQUENCE&#123;r,s&#125;}) from a {@code 5F37}
   * signature field that is either that raw value or a DER-wrapped X.509 SignatureValue
   * ({@code SEQUENCE&#123;AlgorithmIdentifier, BIT STRING&#123;ECDSA-Sig-Value&#125;&#125;}).
   */
  private static byte[] unwrapCvcSignature(byte[] signatureField) {
    try {
      ASN1Primitive parsed = ASN1Primitive.fromByteArray(signatureField);
      if (parsed instanceof ASN1Sequence) {
        ASN1Sequence sequence = (ASN1Sequence) parsed;
        if (sequence.size() == 2
            && sequence.getObjectAt(0) instanceof ASN1Sequence
            && sequence.getObjectAt(1) instanceof ASN1BitString) {
          return ((ASN1BitString) sequence.getObjectAt(1)).getOctets();
        }
      }
    } catch (Exception e) {
      // Not DER-wrapped; treat the field as a raw ECDSA-Sig-Value.
    }
    return signatureField;
  }

  /** Extracts the uncompressed card SM public point ({@code 04 || X || Y}) from a CVC. */
  static byte[] extractCardPublicPoint(byte[] cvc) {
    int[] outer = locateTlv(cvc, 0, TAG_CVC);
    if (outer == null) {
      throw new IllegalArgumentException("CVC missing 7F21");
    }
    int[] keyTemplate = locateTlv(cvc, outer[1], TAG_CVC_PUBLIC_KEY);
    if (keyTemplate == null) {
      throw new IllegalArgumentException("CVC missing 7F49 public key template");
    }
    int[] point = locateTlv(cvc, keyTemplate[1], TAG_CVC_PUBLIC_POINT);
    if (point == null) {
      throw new IllegalArgumentException("CVC missing 86 public point");
    }
    return Arrays.copyOfRange(cvc, point[1], point[1] + point[2]);
  }

  // ---------------------------------------------------------------------------------------------
  // OPACITY CS2 establishment (host side)
  // ---------------------------------------------------------------------------------------------

  /** Result of a successful OPACITY establishment: the four 16-byte session keys. */
  static final class SessionKeys {
    final byte[] skCfrm;
    final byte[] skMac;
    final byte[] skEnc;
    final byte[] skRmac;

    SessionKeys(byte[] skCfrm, byte[] skMac, byte[] skEnc, byte[] skRmac) {
      this.skCfrm = skCfrm;
      this.skMac = skMac;
      this.skEnc = skEnc;
      this.skRmac = skRmac;
    }
  }

  static X9ECParameters p256() {
    return SECNamedCurves.getByName("secp256r1");
  }

  /** Encodes a P-256 public point as the uncompressed {@code 04 || X || Y} octet string. */
  static byte[] encodePoint(ECPoint point) {
    return point.getEncoded(false);
  }

  /** Builds the 74-byte witness payload ({@code idH(8 zeros) || 04 || Xeh || Yeh}). */
  static byte[] buildWitness(byte[] hostPublicPoint) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(new byte[8], 0, 8); // idH = 8 zero bytes
    out.write(hostPublicPoint, 0, hostPublicPoint.length);
    return out.toByteArray();
  }

  /** SHA-256 of the raw CVC bytes, first 8 bytes (idSicc). */
  static byte[] computeIdSicc(byte[] cvcRaw) {
    return Arrays.copyOf(sha256(cvcRaw), 8);
  }

  /**
   * Derives the four CS2 session keys exactly as the applet's {@code deriveCs2SessionKeys} and the
   * .NET {@code DeriveOpacityKeys}: two SHA-256 rounds over a 97-byte input. The KDF input ends with
   * {@code 10 || NIcc(16) || 01 || cbIcc(00)}, where NIcc is the card-supplied nonce.
   *
   * @param sharedSecret 32-byte ECDH shared secret (Z)
   * @param idH 8-byte host identifier (zeros in this profile)
   * @param hostPublicPoint host ephemeral point {@code 04 || X || Y}
   * @param idSicc SHA-256(CVC)[0:8]
   * @param nIcc 16-byte card nonce returned in the GENERAL AUTHENTICATE response
   */
  static SessionKeys deriveSessionKeys(
      byte[] sharedSecret, byte[] idH, byte[] hostPublicPoint, byte[] idSicc, byte[] nIcc) {
    byte[] derived = new byte[64];
    System.arraycopy(round(sharedSecret, (byte) 1, idH, hostPublicPoint, idSicc, nIcc), 0, derived, 0, 32);
    System.arraycopy(round(sharedSecret, (byte) 2, idH, hostPublicPoint, idSicc, nIcc), 0, derived, 32, 32);
    return new SessionKeys(
        Arrays.copyOfRange(derived, 0, 16),
        Arrays.copyOfRange(derived, 16, 32),
        Arrays.copyOfRange(derived, 32, 48),
        Arrays.copyOfRange(derived, 48, 64));
  }

  private static byte[] round(
      byte[] sharedSecret, byte counter, byte[] idH, byte[] hostPublicPoint, byte[] idSicc, byte[] nIcc) {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    input.write(0);
    input.write(0);
    input.write(0);
    input.write(counter);
    input.write(sharedSecret, 0, 32);
    // algorithmId for CS2: 04 09 09 09 09
    input.write(new byte[] {0x04, 0x09, 0x09, 0x09, 0x09}, 0, 5);
    input.write(0x08);
    input.write(idH, 0, 8);
    input.write(0x01);
    input.write(0x00);
    input.write(0x10);
    input.write(hostPublicPoint, 1, 16); // X[0..16)
    input.write(0x08);
    input.write(idSicc, 0, 8);
    input.write(0x10);
    input.write(nIcc, 0, 16);
    input.write(0x01);
    input.write(0x00);
    return sha256(input.toByteArray());
  }

  /**
   * Computes the host's expected card authentication cryptogram: CMAC(skCfrm, "KC_1_V" || idSicc ||
   * idH || Xeh || Yeh).
   */
  static byte[] computeAuthCryptogram(
      byte[] skCfrm, byte[] idSicc, byte[] idH, byte[] hostPublicPoint) {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    input.write(KEY_CONFIRMATION_CONTEXT, 0, KEY_CONFIRMATION_CONTEXT.length);
    input.write(idSicc, 0, 8);
    input.write(idH, 0, 8);
    // Xeh || Yeh = hostPublicPoint without the leading 0x04
    input.write(hostPublicPoint, 1, 64);
    return aesCmac(skCfrm, input.toByteArray());
  }

  // ---------------------------------------------------------------------------------------------
  // SM wrap / unwrap (host side; mirrors PIVSecureMessaging and PivSecureMessagingProvider)
  // ---------------------------------------------------------------------------------------------

  /** Mutable SM session counters/MCVs for a host-side client. */
  static final class SmSession {
    final byte[] skMac;
    final byte[] skEnc;
    final byte[] skRmac;
    final byte[] commandMcv = new byte[16];
    final byte[] responseMcv = new byte[16];
    final byte[] encCounter = new byte[16];
    byte lastCla;
    byte lastIns;

    SmSession(SessionKeys keys) {
      this.skMac = keys.skMac;
      this.skEnc = keys.skEnc;
      this.skRmac = keys.skRmac;
      encCounter[15] = 1;
    }
  }

  /**
   * Wraps a plaintext APDU (header + optional data + Le) into an SM-protected command APDU with CLA
   * 0x0C.
   */
  static byte[] wrapCommand(
      SmSession session, byte ins, byte p1, byte p2, byte[] data, boolean expectLe) {
    session.lastCla = (byte) 0x0C;
    session.lastIns = ins;

    ByteArrayOutputStream dataField = new ByteArrayOutputStream();
    ByteArrayOutputStream macInput = new ByteArrayOutputStream();
    macInput.write(session.commandMcv, 0, 16);
    byte[] header = new byte[16];
    header[0] = 0x0C;
    header[1] = ins;
    header[2] = p1;
    header[3] = p2;
    header[4] = (byte) 0x80;
    macInput.write(header, 0, 16);

    if (data != null && data.length > 0) {
      byte[] iv = computeIv(session, false);
      byte[] padded = isoPad(data);
      byte[] ciphertext = aesCbc(true, session.skEnc, iv, padded);
      byte[] value = new byte[ciphertext.length + 1];
      value[0] = 0x01;
      System.arraycopy(ciphertext, 0, value, 1, ciphertext.length);
      byte[] encTlv = tlv(0x87, value);
      dataField.write(encTlv, 0, encTlv.length);
      macInput.write(encTlv, 0, encTlv.length);
    }

    if (expectLe) {
      byte[] leTlv = tlv(0x97, new byte[] {0x00});
      dataField.write(leTlv, 0, leTlv.length);
      macInput.write(leTlv, 0, leTlv.length);
    }

    byte[] fullMac = aesCmac(session.skMac, macInput.toByteArray());
    System.arraycopy(fullMac, 0, session.commandMcv, 0, 16);
    byte[] macTlv = tlv(0x8E, Arrays.copyOf(fullMac, 8));
    dataField.write(macTlv, 0, macTlv.length);

    byte[] body = dataField.toByteArray();
    ByteArrayOutputStream apdu = new ByteArrayOutputStream();
    apdu.write(0x0C);
    apdu.write(ins & 0xFF);
    apdu.write(p1 & 0xFF);
    apdu.write(p2 & 0xFF);
    apdu.write(body.length);
    apdu.write(body, 0, body.length);
    apdu.write(0x00); // Le
    return apdu.toByteArray();
  }

  /** Holds the plaintext result of an unwrapped SM response. */
  static final class SmResponse {
    final byte[] data;
    final int statusWord;

    SmResponse(byte[] data, int statusWord) {
      this.data = data;
      this.statusWord = statusWord;
    }
  }

  /** Unwraps an SM response APDU (data || SW). Verifies the RMAC and decrypts. */
  static SmResponse unwrapResponse(SmSession session, byte[] response) {
    if (response.length < 2) {
      throw new IllegalArgumentException("SM response too short");
    }
    int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    byte[] body = Arrays.copyOf(response, response.length - 2);
    if (sw != 0x9000) {
      // Errors may be returned unwrapped by the transport; surface as-is.
      return new SmResponse(new byte[0], sw);
    }

    int cursor = 0;
    int end = body.length;
    int encOffset = -1;
    int encLength = 0;
    int statusOffset = -1;
    int macValueOffset = -1;
    ByteArrayOutputStream rmacInput = new ByteArrayOutputStream();
    rmacInput.write(session.responseMcv, 0, 16);

    while (cursor < end) {
      int tag = body[cursor] & 0xFF;
      int[] tlv = readTlvHeader(body, cursor);
      int valueOffset = tlv[0];
      int length = tlv[1];
      int next = valueOffset + length;
      if (tag == 0x87) {
        encOffset = valueOffset;
        encLength = length;
        rmacInput.write(body, cursor, next - cursor);
      } else if (tag == 0x99) {
        statusOffset = valueOffset;
        rmacInput.write(body, cursor, next - cursor);
      } else if (tag == 0x8E) {
        macValueOffset = valueOffset;
      }
      cursor = next;
    }

    if (macValueOffset < 0 || statusOffset < 0) {
      throw new IllegalStateException("SM response missing status or MAC");
    }
    byte[] fullRmac = aesCmac(session.skRmac, rmacInput.toByteArray());
    for (int i = 0; i < 8; i++) {
      if (fullRmac[i] != body[macValueOffset + i]) {
        throw new IllegalStateException("SM response MAC mismatch");
      }
    }
    System.arraycopy(fullRmac, 0, session.responseMcv, 0, 16);

    int statusSw =
        ((body[statusOffset] & 0xFF) << 8) | (body[statusOffset + 1] & 0xFF);

    byte[] plaintext = new byte[0];
    if (encOffset >= 0) {
      if (body[encOffset] != 0x01) {
        throw new IllegalStateException("SM response bad padding indicator");
      }
      byte[] iv = computeIv(session, true);
      byte[] ciphertext = Arrays.copyOfRange(body, encOffset + 1, encOffset + encLength);
      byte[] decrypted = aesCbc(false, session.skEnc, iv, ciphertext);
      plaintext = isoUnpad(decrypted);
    }

    if (shouldIncrementCounter(session)) {
      incrementCounter(session.encCounter);
    }
    return new SmResponse(plaintext, statusSw);
  }

  private static boolean shouldIncrementCounter(SmSession session) {
    if ((session.lastIns & 0xFF) == 0xC0) {
      return false;
    }
    return session.lastCla != (byte) 0x1C;
  }

  private static byte[] computeIv(SmSession session, boolean response) {
    byte[] counter = Arrays.copyOf(session.encCounter, 16);
    if (response) {
      counter[0] = (byte) (counter[0] | 0x80);
    }
    return aesEcbBlock(session.skEnc, counter);
  }

  private static void incrementCounter(byte[] counter) {
    for (int i = 15; i >= 0; i--) {
      counter[i]++;
      if (counter[i] != 0) {
        return;
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Primitives
  // ---------------------------------------------------------------------------------------------

  static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] aesCmac(byte[] key, byte[] data) {
    CMac mac = new CMac(AESEngine.newInstance());
    mac.init(new KeyParameter(key));
    mac.update(data, 0, data.length);
    byte[] out = new byte[mac.getMacSize()];
    mac.doFinal(out, 0);
    return out;
  }

  private static byte[] aesEcbBlock(byte[] key, byte[] block) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      return cipher.doFinal(block);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] aesCbc(boolean encrypt, byte[] key, byte[] iv, byte[] input) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(
          encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new IvParameterSpec(iv));
      return cipher.doFinal(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] isoPad(byte[] input) {
    int paddingLength = 16 - (input.length % 16);
    byte[] padded = new byte[input.length + paddingLength];
    System.arraycopy(input, 0, padded, 0, input.length);
    padded[input.length] = (byte) 0x80;
    return padded;
  }

  private static byte[] isoUnpad(byte[] input) {
    for (int i = input.length - 1; i >= 0; i--) {
      if (input[i] == (byte) 0x80) {
        return Arrays.copyOf(input, i);
      }
      if (input[i] != 0x00) {
        break;
      }
    }
    throw new IllegalStateException("Invalid ISO 7816 padding");
  }

  // ---------------------------------------------------------------------------------------------
  // Minimal BER-TLV (single/double-byte tags, up to 3-byte length)
  // ---------------------------------------------------------------------------------------------

  static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTlv(out, tag, value);
    return out.toByteArray();
  }

  private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] value) {
    if (tag > 0xFF) {
      out.write((tag >> 8) & 0xFF);
    }
    out.write(tag & 0xFF);
    int length = value.length;
    if (length < 0x80) {
      out.write(length);
    } else if (length <= 0xFF) {
      out.write(0x81);
      out.write(length);
    } else {
      out.write(0x82);
      out.write((length >> 8) & 0xFF);
      out.write(length & 0xFF);
    }
    out.write(value, 0, value.length);
  }

  /** Reads a TLV header at {@code offset}; returns {@code {valueOffset, length}}. */
  private static int[] readTlvHeader(byte[] data, int offset) {
    int cursor = offset;
    int first = data[cursor++] & 0xFF;
    if ((first & 0x1F) == 0x1F) {
      cursor++; // two-byte tag
    }
    int lengthByte = data[cursor++] & 0xFF;
    int length;
    if (lengthByte < 0x80) {
      length = lengthByte;
    } else if (lengthByte == 0x81) {
      length = data[cursor++] & 0xFF;
    } else if (lengthByte == 0x82) {
      length = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);
    } else {
      throw new IllegalArgumentException("Unsupported TLV length form");
    }
    return new int[] {cursor, length};
  }

  /**
   * Locates the first TLV with the given tag scanning forward from {@code offset}; returns {@code
   * {tagOffset, valueOffset, length}} or null.
   */
  static int[] locateTlv(byte[] data, int offset, int tag) {
    int cursor = offset;
    while (cursor < data.length) {
      int tagOffset = cursor;
      int first = data[cursor++] & 0xFF;
      int currentTag = first;
      if ((first & 0x1F) == 0x1F) {
        currentTag = (first << 8) | (data[cursor++] & 0xFF);
      }
      int lengthByte = data[cursor++] & 0xFF;
      int length;
      if (lengthByte < 0x80) {
        length = lengthByte;
      } else if (lengthByte == 0x81) {
        length = data[cursor++] & 0xFF;
      } else if (lengthByte == 0x82) {
        length = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);
      } else {
        throw new IllegalArgumentException("Unsupported TLV length form");
      }
      if (currentTag == tag) {
        return new int[] {tagOffset, cursor, length};
      }
      cursor += length;
    }
    return null;
  }

  static byte[] issuerIdFromPublicKey(PublicKey signerPublicKey) {
    // issuer-id = SHA-256(SubjectPublicKeyInfo)[0:8]
    return Arrays.copyOf(sha256(signerPublicKey.getEncoded()), 8);
  }
}
