/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.common.HexUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Durable per-card F9 attestation authority identity.
 *
 * <p>Each cardstock mint allocates 16 random bytes, encoded as 32 uppercase hex digits. That value
 * is used as the F9 certificate serial number and as a {@code serialNumber} RDN on the F9 subject
 * so every attestation leaf issuer is self-labeling.
 */
public final class F9InstanceId {
  public static final int LENGTH_BYTES = 16;

  private final byte[] bytes;

  private F9InstanceId(byte[] bytes) {
    if (bytes == null || bytes.length != LENGTH_BYTES) {
      throw new IllegalArgumentException(
          "F9 instance id must be exactly " + LENGTH_BYTES + " bytes");
    }
    this.bytes = Arrays.copyOf(bytes, bytes.length);
  }

  public static F9InstanceId generate() {
    byte[] generated = new byte[LENGTH_BYTES];
    new SecureRandom().nextBytes(generated);
    return new F9InstanceId(generated);
  }

  public static F9InstanceId fromHex(String hex) {
    byte[] decoded = HexUtil.parse(hex);
    if (decoded.length != LENGTH_BYTES) {
      throw new IllegalArgumentException(
          "F9 instance id hex must decode to " + LENGTH_BYTES + " bytes");
    }
    return new F9InstanceId(decoded);
  }

  public static F9InstanceId fromSerialNumber(BigInteger serial) {
    if (serial == null || serial.signum() <= 0) {
      throw new IllegalArgumentException("F9 certificate serial must be a positive integer");
    }
    byte[] raw = serial.toByteArray();
    int start = 0;
    if (raw.length > LENGTH_BYTES && raw[0] == 0) {
      start = 1;
    }
    int length = raw.length - start;
    if (length > LENGTH_BYTES) {
      throw new IllegalArgumentException(
          "F9 certificate serial is longer than " + LENGTH_BYTES + " bytes");
    }
    byte[] padded = new byte[LENGTH_BYTES];
    System.arraycopy(raw, start, padded, LENGTH_BYTES - length, length);
    return new F9InstanceId(padded);
  }

  public String toHex() {
    return HexUtil.format(bytes);
  }

  public byte[] toBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }

  /** Positive certificate serial number derived from the instance id bytes. */
  public BigInteger toSerialNumber() {
    return new BigInteger(1, bytes);
  }

  /**
   * Builds the F9 subject by appending {@code serialNumber=<instanceId>} to the operator template.
   *
   * @throws IllegalArgumentException if the template already contains a serialNumber RDN
   */
  public X500Name composeSubject(String baseTemplate) {
    if (baseTemplate == null || baseTemplate.trim().isEmpty()) {
      throw new IllegalArgumentException("F9 subject template is required");
    }
    X500Name base = new X500Name(baseTemplate.trim());
    if (hasSerialNumberRdn(base)) {
      throw new IllegalArgumentException(
          "F9 subject template must not include serialNumber; it is appended per card ("
              + baseTemplate
              + ")");
    }
    // Append as the most-specific RDN. RFC 2253 string form lists that component first.
    return new X500Name("SERIALNUMBER=" + toHex() + "," + base.toString());
  }

  public static boolean hasSerialNumberRdn(X500Name name) {
    return name.getRDNs(BCStyle.SERIALNUMBER).length > 0;
  }

  /**
   * Prefer the {@code serialNumber} RDN when present; otherwise derive from the certificate serial.
   */
  public static F9InstanceId extractFromCertificate(X509Certificate certificate) {
    if (certificate == null) {
      throw new IllegalArgumentException("certificate is required");
    }
    X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
    Optional<F9InstanceId> fromRdn = fromSerialNumberRdn(subject);
    if (fromRdn.isPresent()) {
      return fromRdn.get();
    }
    return fromSerialNumber(certificate.getSerialNumber());
  }

  /** Parse an attestation leaf and extract instance id from its issuer name. */
  public static Optional<F9InstanceId> extractFromLeafIssuer(byte[] leafDer) {
    if (leafDer == null || leafDer.length == 0) {
      return Optional.empty();
    }
    try {
      X509CertificateHolder holder = new X509CertificateHolder(leafDer);
      return fromSerialNumberRdn(holder.getIssuer());
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  public static Optional<F9InstanceId> fromSerialNumberRdn(X500Name name) {
    RDN[] rdns = name.getRDNs(BCStyle.SERIALNUMBER);
    if (rdns.length == 0) {
      return Optional.empty();
    }
    String value = IETFUtils.valueToString(rdns[0].getFirst().getValue()).trim();
    if (value.startsWith("#")) {
      return Optional.empty();
    }
    try {
      return Optional.of(fromHex(value));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  public static boolean subjectsMatch(X509Certificate f9Cert, byte[] leafDer) {
    try {
      X509CertificateHolder leaf = new X509CertificateHolder(leafDer);
      X500Name expected = X500Name.getInstance(f9Cert.getSubjectX500Principal().getEncoded());
      return expected.equals(leaf.getIssuer());
    } catch (IOException e) {
      return false;
    }
  }

  public static X509Certificate parseCertificate(byte[] der) throws CertificateException {
    try {
      return new JcaX509CertificateConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCertificate(new X509CertificateHolder(der));
    } catch (IOException e) {
      throw new CertificateException("Unable to parse certificate DER", e);
    }
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof F9InstanceId)) {
      return false;
    }
    return Arrays.equals(bytes, ((F9InstanceId) other).bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return toHex();
  }
}
