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

import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.CryptoProviders;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Host-side PIV secure-messaging CVC and VCI trust-anchor helpers.
 *
 * <p>Mirrors the PD validation path used for VCI trust-anchor chain checks: direct (CVC signed by
 * loaded anchor) and intermediate (CVC signed by Intermediate CVC which is signed by the anchor).
 * These checks are host/middleware concerns, not card APDU processing.
 *
 * <p>Aligned with NIST SP 800-73-5 Part 2 Section 4.1.5 (Secure Messaging CVC) and the OSDP VCI
 * trust-anchor record profile ({@code 7F50}).
 */
final class VciCvcSupport {

  static final String OID_EC_P256 = "1.2.840.10045.3.1.7";
  static final String OID_EC_P384 = "1.3.132.0.34";
  static final String OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
  static final String OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
  static final String OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
  static final String OID_RSA_SHA384 = "1.2.840.113549.1.1.12";

  static final int TAG_ANCHOR = 0x7F50;
  static final int TAG_PROFILE = 0x80;
  static final int TAG_CERT = 0x70;
  static final int TAG_CERT_INFO = 0x71;

  static {
    CryptoProviders.ensureBouncyCastle();
  }

  private VciCvcSupport() {}

  // ---------------------------------------------------------------------------------------------
  // Parsed structures
  // ---------------------------------------------------------------------------------------------

  static final class ParsedCvc {
    final byte[] raw;
    final byte[] tbs;
    final byte[] profile;
    final byte[] iin;
    final byte[] subjectIdentifier;
    final byte[] role;
    final String publicKeyCurveOid;
    final String signatureAlgorithmOid;
    final byte[] signature;
    final PublicKey publicKey;

    ParsedCvc(
        byte[] raw,
        byte[] tbs,
        byte[] profile,
        byte[] iin,
        byte[] subjectIdentifier,
        byte[] role,
        String publicKeyCurveOid,
        String signatureAlgorithmOid,
        byte[] signature,
        PublicKey publicKey) {
      this.raw = raw;
      this.tbs = tbs;
      this.profile = profile;
      this.iin = iin;
      this.subjectIdentifier = subjectIdentifier;
      this.role = role;
      this.publicKeyCurveOid = publicKeyCurveOid;
      this.signatureAlgorithmOid = signatureAlgorithmOid;
      this.signature = signature;
      this.publicKey = publicKey;
    }
  }

  static final class TrustAnchor {
    final byte[] iin;
    final byte[] spki;
    final PublicKey publicKey;
    final int recordLength;

    TrustAnchor(byte[] iin, byte[] spki, PublicKey publicKey, int recordLength) {
      this.iin = iin;
      this.spki = spki;
      this.publicKey = publicKey;
      this.recordLength = recordLength;
    }
  }

  static final class Smcs {
    final X509Certificate certificate;
    final byte[] certificateDer;
    final ParsedCvc intermediateCvc;
    final byte[] intermediateRaw;

    Smcs(
        X509Certificate certificate,
        byte[] certificateDer,
        ParsedCvc intermediateCvc,
        byte[] intermediateRaw) {
      this.certificate = certificate;
      this.certificateDer = certificateDer;
      this.intermediateCvc = intermediateCvc;
      this.intermediateRaw = intermediateRaw;
    }
  }

  static final class PdValidationResult {
    final boolean passed;
    final String path;
    final String reason;
    final List<String> checksPassed;
    final List<String> checksFailed;

    PdValidationResult(
        boolean passed,
        String path,
        String reason,
        List<String> checksPassed,
        List<String> checksFailed) {
      this.passed = passed;
      this.path = path;
      this.reason = reason;
      this.checksPassed = checksPassed;
      this.checksFailed = checksFailed;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Parse
  // ---------------------------------------------------------------------------------------------

  static ParsedCvc parseCvc(byte[] data) {
    int[] outer = VciSupport.locateTlv(data, 0, VciSupport.TAG_CVC);
    if (outer == null || outer[1] + outer[2] != data.length) {
      // Allow trailing? Require single top-level 7F21 spanning the blob.
      if (outer == null) {
        throw new IllegalArgumentException("CVC missing 7F21");
      }
    }
    int valueOffset = outer[1];
    int valueEnd = outer[1] + outer[2];
    if (valueEnd != data.length) {
      throw new IllegalArgumentException("CVC must be a single 7F21 object");
    }

    ByteArrayOutputStream tbs = new ByteArrayOutputStream();
    byte[] profile = null;
    byte[] iin = null;
    byte[] subject = null;
    byte[] role = null;
    byte[] keyTemplate = null;
    byte[] signatureField = null;

    int cursor = valueOffset;
    while (cursor < valueEnd) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(data, cursor, valueEnd);
      byte[] value = Arrays.copyOfRange(data, tlv.valueOffset, tlv.nextOffset);
      if (tlv.tag != VciSupport.TAG_CVC_SIGNATURE) {
        tbs.write(data, tlv.tagOffset, tlv.nextOffset - tlv.tagOffset);
      }
      if (tlv.tag == VciSupport.TAG_CVC_PROFILE) {
        profile = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_ISSUER_ID) {
        iin = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_SUBJECT_ID) {
        subject = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_ROLE) {
        role = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_PUBLIC_KEY) {
        keyTemplate = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_SIGNATURE) {
        signatureField = value;
      }
      cursor = tlv.nextOffset;
    }
    if (keyTemplate == null || signatureField == null) {
      throw new IllegalArgumentException("CVC missing public key or signature");
    }
    String curveOid = null;
    byte[] point = null;
    int k = 0;
    while (k < keyTemplate.length) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(keyTemplate, k);
      byte[] value = Arrays.copyOfRange(keyTemplate, tlv.valueOffset, tlv.nextOffset);
      if (tlv.tag == VciSupport.TAG_CVC_PUBLIC_KEY_OID) {
        curveOid = decodeOid(value);
      } else if (tlv.tag == VciSupport.TAG_CVC_PUBLIC_POINT) {
        point = value;
      }
      k = tlv.nextOffset;
    }
    if (curveOid == null || point == null) {
      throw new IllegalArgumentException("CVC public key missing OID or point");
    }
    SignatureParts sig = parseSignatureField(signatureField);
    PublicKey publicKey = ecPublicKeyFromPoint(curveOid, point);
    return new ParsedCvc(
        data,
        tbs.toByteArray(),
        profile == null ? new byte[0] : profile,
        iin == null ? new byte[0] : iin,
        subject == null ? new byte[0] : subject,
        role == null ? new byte[0] : role,
        curveOid,
        sig.algorithmOid,
        sig.signature,
        publicKey);
  }

  static TrustAnchor parseAnchor(byte[] data) {
    int[] outer = VciSupport.locateTlv(data, 0, TAG_ANCHOR);
    if (outer == null || outer[1] + outer[2] != data.length) {
      throw new IllegalArgumentException("anchor must be a single 7F50 record");
    }
    byte[] iin = null;
    byte[] spki = null;
    int cursor = outer[1];
    int end = outer[1] + outer[2];
    while (cursor < end) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(data, cursor, end);
      byte[] value = Arrays.copyOfRange(data, tlv.valueOffset, tlv.nextOffset);
      if (tlv.tag == TAG_PROFILE) {
        if (value.length != 1 || value[0] != 0x01) {
          throw new IllegalArgumentException("unsupported trust anchor profile");
        }
      } else if (tlv.tag == VciSupport.TAG_CVC_ISSUER_ID) {
        iin = value;
      } else if (tlv.tag == VciSupport.TAG_CVC_PUBLIC_KEY) {
        spki = value;
      }
      cursor = tlv.nextOffset;
    }
    if (iin == null || iin.length != 8 || spki == null) {
      throw new IllegalArgumentException("trust anchor missing IIN or SPKI");
    }
    try {
      PublicKey publicKey =
          KeyFactory.getInstance(detectKeyAlg(spki), "BC")
              .generatePublic(new X509EncodedKeySpec(spki));
      return new TrustAnchor(iin, spki, publicKey, data.length);
    } catch (Exception e) {
      throw new IllegalArgumentException("failed to parse trust anchor SPKI", e);
    }
  }

  static Smcs parseSmcs(byte[] data) {
    // May be 53 wrapper or raw body containing 70/71/7F21.
    byte[] body = data;
    int[] outer53 = VciSupport.locateTlv(data, 0, 0x53);
    if (outer53 != null && outer53[1] + outer53[2] == data.length) {
      body = Arrays.copyOfRange(data, outer53[1], outer53[1] + outer53[2]);
    }
    byte[] certDer = null;
    byte[] intermediateRaw = null;
    int cursor = 0;
    while (cursor < body.length) {
      BerTlvReader.Tlv tlv = BerTlvReader.read(body, cursor);
      if (tlv.tag == TAG_CERT) {
        certDer = Arrays.copyOfRange(body, tlv.valueOffset, tlv.nextOffset);
      } else if (tlv.tag == VciSupport.TAG_CVC) {
        intermediateRaw = Arrays.copyOfRange(body, tlv.tagOffset, tlv.nextOffset);
      }
      cursor = tlv.nextOffset;
    }
    X509Certificate certificate = null;
    byte[] resolvedCert = null;
    if (certDer != null) {
      resolvedCert = tryLoadCertificate(certDer);
      if (resolvedCert != null) {
        try {
          CertificateFactory cf = CertificateFactory.getInstance("X.509");
          certificate =
              (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(resolvedCert));
        } catch (Exception e) {
          throw new IllegalArgumentException("unable to parse 5FC122 certificate", e);
        }
      } else {
        throw new IllegalArgumentException("unable to parse 5FC122 certificate");
      }
    }
    ParsedCvc intermediate = intermediateRaw == null ? null : parseCvc(intermediateRaw);
    return new Smcs(certificate, resolvedCert, intermediate, intermediateRaw);
  }

  /**
   * PD-side CVC chain validation: direct path when CVC IIN matches anchor IIN, otherwise one-hop
   * intermediate path via 5FC122.
   */
  static PdValidationResult validatePdChain(TrustAnchor anchor, ParsedCvc secureCvc, Smcs smcs) {
    List<String> passed = new ArrayList<>();
    List<String> failed = new ArrayList<>();

    boolean directIin = Arrays.equals(secureCvc.iin, anchor.iin);
    if (directIin) {
      passed.add("secure_cvc_iin_matches_anchor_iin");
      boolean ok =
          verifySignature(
              anchor.publicKey,
              secureCvc.signatureAlgorithmOid,
              secureCvc.signature,
              secureCvc.tbs);
      if (ok) {
        passed.add("secure_cvc_signature_with_anchor");
        return new PdValidationResult(true, "direct", null, passed, failed);
      }
      failed.add("secure_cvc_signature_with_anchor");
      return new PdValidationResult(
          false, "direct", "signature verification failed", passed, failed);
    }
    failed.add("secure_cvc_iin_matches_anchor_iin");

    if (smcs == null) {
      failed.add("5fc122_present");
      return new PdValidationResult(
          false, "intermediate", "no 5FC122 for intermediate path", passed, failed);
    }
    passed.add("5fc122_present");
    if (smcs.intermediateCvc == null) {
      failed.add("intermediate_cvc_present");
      return new PdValidationResult(
          false, "intermediate", "5FC122 has no Intermediate CVC", passed, failed);
    }
    passed.add("intermediate_cvc_present");

    ParsedCvc intermediate = smcs.intermediateCvc;
    if (Arrays.equals(secureCvc.iin, intermediate.subjectIdentifier)) {
      passed.add("secure_cvc_iin_matches_intermediate_subject_identifier");
    } else {
      failed.add("secure_cvc_iin_matches_intermediate_subject_identifier");
    }
    if (intermediate.role.length == 1 && intermediate.role[0] == 0x12) {
      passed.add("intermediate_role_is_12");
    } else {
      failed.add("intermediate_role_is_12");
    }
    if (Arrays.equals(intermediate.iin, anchor.iin)) {
      passed.add("intermediate_iin_matches_anchor_iin");
    } else {
      failed.add("intermediate_iin_matches_anchor_iin");
    }
    if (!failed.isEmpty()
        && (failed.contains("secure_cvc_iin_matches_intermediate_subject_identifier")
            || failed.contains("intermediate_role_is_12")
            || failed.contains("intermediate_iin_matches_anchor_iin"))) {
      return new PdValidationResult(
          false, "intermediate", "intermediate CVC selector checks failed", passed, failed);
    }

    boolean okI =
        verifySignature(
            anchor.publicKey,
            intermediate.signatureAlgorithmOid,
            intermediate.signature,
            intermediate.tbs);
    if (okI) {
      passed.add("intermediate_cvc_signature_with_anchor");
    } else {
      failed.add("intermediate_cvc_signature_with_anchor");
    }
    boolean okC =
        verifySignature(
            intermediate.publicKey,
            secureCvc.signatureAlgorithmOid,
            secureCvc.signature,
            secureCvc.tbs);
    if (okC) {
      passed.add("secure_cvc_signature_with_intermediate");
    } else {
      failed.add("secure_cvc_signature_with_intermediate");
    }
    boolean ok = okI && okC;
    return new PdValidationResult(
        ok, "intermediate", ok ? null : "intermediate chain signature failed", passed, failed);
  }

  static boolean verifySignature(
      PublicKey publicKey, String algorithmOid, byte[] signature, byte[] tbs) {
    try {
      String jca;
      if (OID_ECDSA_SHA256.equals(algorithmOid)) {
        jca = "SHA256withECDSA";
      } else if (OID_ECDSA_SHA384.equals(algorithmOid)) {
        jca = "SHA384withECDSA";
      } else if (OID_RSA_SHA256.equals(algorithmOid)) {
        jca = "SHA256withRSA";
      } else if (OID_RSA_SHA384.equals(algorithmOid)) {
        jca = "SHA384withRSA";
      } else {
        return false;
      }
      Signature verifier = Signature.getInstance(jca, "BC");
      verifier.initVerify(publicKey);
      verifier.update(tbs);
      return verifier.verify(signature);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "unable to verify CVC signature using algorithm OID " + algorithmOid, e);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------------------------

  static final class SignatureParts {
    final String algorithmOid;
    final byte[] signature;

    SignatureParts(String algorithmOid, byte[] signature) {
      this.algorithmOid = algorithmOid;
      this.signature = signature;
    }
  }

  static SignatureParts parseSignatureField(byte[] signatureField) {
    try {
      ASN1Primitive parsed = ASN1Primitive.fromByteArray(signatureField);
      if (parsed instanceof ASN1Sequence) {
        ASN1Sequence sequence = (ASN1Sequence) parsed;
        if (sequence.size() == 2
            && sequence.getObjectAt(0) instanceof ASN1Sequence
            && sequence.getObjectAt(1) instanceof ASN1BitString) {
          ASN1Sequence algId = (ASN1Sequence) sequence.getObjectAt(0);
          ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(algId.getObjectAt(0));
          byte[] sig = ((ASN1BitString) sequence.getObjectAt(1)).getOctets();
          return new SignatureParts(oid.getId(), sig);
        }
      }
    } catch (Exception e) {
      // fall through
    }
    throw new IllegalArgumentException(
        "CVC signature must be DigitalSignature AlgorithmIdentifier wrapper");
  }

  private static PublicKey ecPublicKeyFromPoint(String curveOid, byte[] point) {
    try {
      String name;
      if (OID_EC_P256.equals(curveOid)) {
        name = "secp256r1";
      } else if (OID_EC_P384.equals(curveOid)) {
        name = "secp384r1";
      } else {
        throw new IllegalArgumentException("unsupported curve OID " + curveOid);
      }
      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(name);
      ECPoint q = spec.getCurve().decodePoint(point);
      ECPublicKeySpec keySpec = new ECPublicKeySpec(q, spec);
      return KeyFactory.getInstance("EC", "BC").generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalArgumentException("failed to build EC public key", e);
    }
  }

  private static String detectKeyAlg(byte[] spki) {
    try {
      ASN1Sequence seq = ASN1Sequence.getInstance(spki);
      ASN1Sequence algId = ASN1Sequence.getInstance(seq.getObjectAt(0));
      String oid = ASN1ObjectIdentifier.getInstance(algId.getObjectAt(0)).getId();
      if (oid.startsWith("1.2.840.113549.1.1")) {
        return "RSA";
      }
      return "EC";
    } catch (Exception e) {
      return "EC";
    }
  }

  private static byte[] tryLoadCertificate(byte[] certDer) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cf.generateCertificate(new ByteArrayInputStream(certDer));
      return certDer;
    } catch (Exception ignored) {
      // try gzip
    }
    try {
      GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(certDer));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buf = new byte[512];
      int n;
      while ((n = gzip.read(buf)) >= 0) {
        out.write(buf, 0, n);
      }
      byte[] inflated = out.toByteArray();
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cf.generateCertificate(new ByteArrayInputStream(inflated));
      return inflated;
    } catch (Exception e) {
      return null;
    }
  }

  static String decodeOid(byte[] value) {
    if (value.length == 0) {
      throw new IllegalArgumentException("empty OID");
    }
    int first = value[0] & 0xFF;
    StringBuilder sb = new StringBuilder();
    sb.append(first / 40).append('.').append(first % 40);
    long acc = 0;
    for (int i = 1; i < value.length; i++) {
      int b = value[i] & 0xFF;
      acc = (acc << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) {
        sb.append('.').append(acc);
        acc = 0;
      }
    }
    return sb.toString();
  }

  static String toHex(byte[] data) {
    return HexUtil.format(data);
  }
}
