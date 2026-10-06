/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Strict Distinguished Encoding Rules (X.690 Section 10) gate for attestation inputs.
 *
 * <p>An input is accepted only when it is exactly one ASN.1 object, carries no trailing octets, and
 * its DER re-encoding is byte-identical to the input. Indefinite lengths, non-minimal lengths,
 * non-canonical BOOLEAN values, unsorted SET OF members and every other BER-only form are therefore
 * rejected.
 */
public final class StrictDer {
  /** PEM label of an X.509 certificate block (RFC 7468 Section 5.1). */
  public static final String PEM_CERTIFICATE = "CERTIFICATE";

  private StrictDer() {}

  /**
   * Parses {@code der} as a single DER object.
   *
   * @throws IllegalArgumentException when the input is empty, is not a single complete ASN.1
   *     object, has trailing octets, or differs from its DER re-encoding
   */
  public static ASN1Primitive parse(byte[] der) {
    if (der == null || der.length == 0) {
      throw new IllegalArgumentException("DER input is empty");
    }
    ASN1Primitive object;
    try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der), der.length)) {
      object = in.readObject();
      if (object == null) {
        throw new IllegalArgumentException("DER input holds no object");
      }
      if (in.readObject() != null) {
        throw new IllegalArgumentException("DER input has trailing bytes");
      }
    } catch (IOException | RuntimeException e) {
      if (e instanceof IllegalArgumentException) {
        throw (IllegalArgumentException) e;
      }
      throw new IllegalArgumentException("DER input is malformed: " + e.getMessage(), e);
    }
    byte[] reencoded;
    try {
      reencoded = object.getEncoded(ASN1Encoding.DER);
    } catch (IOException e) {
      throw new IllegalArgumentException("DER input cannot be re-encoded: " + e.getMessage(), e);
    }
    if (reencoded.length != der.length) {
      throw new IllegalArgumentException(
          "DER input has trailing bytes or non-DER lengths ("
              + der.length
              + " bytes, DER form "
              + reencoded.length
              + " bytes)");
    }
    if (!Arrays.equals(reencoded, der)) {
      throw new IllegalArgumentException("DER input is not in distinguished encoding");
    }
    return object;
  }

  /**
   * Parses a DER X.509 certificate after {@link #parse} accepts it.
   *
   * @throws IllegalArgumentException when the input is not strict DER or is not a certificate
   */
  public static X509Certificate parseCertificate(byte[] der) {
    parse(der);
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      X509Certificate certificate =
          (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
      if (!Arrays.equals(certificate.getEncoded(), der)) {
        throw new IllegalArgumentException("certificate encoding was altered by the parser");
      }
      return certificate;
    } catch (CertificateException e) {
      throw new IllegalArgumentException("not an X.509 certificate: " + e.getMessage(), e);
    }
  }

  /**
   * Reads a PEM file holding exactly one PEM block, of type {@code CERTIFICATE}, and returns the
   * decoded block contents without DER validation. Text outside the block is ignored.
   *
   * @throws IOException when the file cannot be read
   * @throws IllegalArgumentException when the file holds no block, more than one block, or a block
   *     of another type
   */
  public static byte[] readSinglePemBlock(Path path) throws IOException {
    PemObject only = null;
    int count = 0;
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
        PemReader pem = new PemReader(reader)) {
      PemObject object;
      while ((object = pem.readPemObject()) != null) {
        count++;
        only = object;
      }
    }
    if (count != 1) {
      throw new IllegalArgumentException(
          path + " must contain exactly one " + PEM_CERTIFICATE + " block, found " + count);
    }
    if (!PEM_CERTIFICATE.equals(only.getType())) {
      throw new IllegalArgumentException(
          path + " holds a " + only.getType() + " block, expected " + PEM_CERTIFICATE);
    }
    return only.getContent();
  }

  /**
   * Reads a PEM file holding exactly one {@code CERTIFICATE} block and parses it with {@link
   * #parseCertificate}.
   */
  public static X509Certificate readSinglePemCertificate(Path path) throws IOException {
    return parseCertificate(readSinglePemBlock(path));
  }
}
