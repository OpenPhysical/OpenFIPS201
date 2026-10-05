/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Immutable input to {@link AttestationVerifier#verify}.
 *
 * <p>Certificates are held as their exact encodings so that {@link AttestationVerifier} applies
 * {@link StrictDer} to the octets that were supplied. Only the trust anchor is mandatory; every
 * other element enables the checks that depend on it. The evaluation time defaults to the moment
 * {@link Builder#build} is called.
 */
public final class VerificationRequest {
  private final byte[] anchor;
  private final byte[] samCertificate;
  private final byte[] f9Certificate;
  private final byte[] leaf;
  private final byte[] slotCertificate;
  private final Opid expectOpid;
  private final OpidSequence sequence;
  private final Long issuanceSeq;
  private final long at;
  private final byte[] chuidValue;
  private final List<String> registry;
  private final List<SignedVoid> voids;

  /** A SAM-signed VOID ledger entry ({@code voids.json}). */
  public static final class SignedVoid {
    private final byte[] entry;
    private final byte[] signature;

    public SignedVoid(byte[] entry, byte[] signature) {
      this.entry = entry.clone();
      this.signature = signature.clone();
    }

    public byte[] entry() {
      return entry.clone();
    }

    public byte[] signature() {
      return signature.clone();
    }
  }

  private VerificationRequest(Builder builder) {
    this.anchor = builder.anchor;
    this.samCertificate = builder.samCertificate;
    this.f9Certificate = builder.f9Certificate;
    this.leaf = builder.leaf;
    this.slotCertificate = builder.slotCertificate;
    this.expectOpid = builder.expectOpid;
    this.sequence = builder.sequence;
    this.issuanceSeq = builder.issuanceSeq;
    this.at = builder.at == null ? System.currentTimeMillis() : builder.at.getTime();
    this.chuidValue = builder.chuidValue;
    this.registry =
        builder.registry == null
            ? null
            : Collections.unmodifiableList(new ArrayList<String>(builder.registry));
    this.voids =
        builder.voids == null
            ? null
            : Collections.unmodifiableList(new ArrayList<SignedVoid>(builder.voids));
  }

  /** The allocation registry lines ({@code allocations.jsonl}), when supplied. */
  public Optional<List<String>> registry() {
    return Optional.ofNullable(registry);
  }

  /** The SAM-signed VOID entries ({@code voids.json}), when supplied. */
  public Optional<List<SignedVoid>> voids() {
    return Optional.ofNullable(voids);
  }

  public static Builder builder() {
    return new Builder();
  }

  public byte[] anchor() {
    return anchor.clone();
  }

  public Optional<byte[]> samCertificate() {
    return copy(samCertificate);
  }

  public Optional<byte[]> f9Certificate() {
    return copy(f9Certificate);
  }

  public Optional<byte[]> leaf() {
    return copy(leaf);
  }

  public Optional<byte[]> slotCertificate() {
    return copy(slotCertificate);
  }

  public Optional<Opid> expectOpid() {
    return Optional.ofNullable(expectOpid);
  }

  public Optional<OpidSequence> sequence() {
    return Optional.ofNullable(sequence);
  }

  /** Expected issuance sequence number; when present it must equal the F9 extension value. */
  public Optional<Long> issuanceSeq() {
    return Optional.ofNullable(issuanceSeq);
  }

  public Date at() {
    return new Date(at);
  }

  public Optional<byte[]> chuidValue() {
    return copy(chuidValue);
  }

  private static Optional<byte[]> copy(byte[] value) {
    return value == null ? Optional.<byte[]>empty() : Optional.of(value.clone());
  }

  /** Builder for {@link VerificationRequest}. */
  public static final class Builder {
    private byte[] anchor;
    private byte[] samCertificate;
    private byte[] f9Certificate;
    private byte[] leaf;
    private byte[] slotCertificate;
    private Opid expectOpid;
    private OpidSequence sequence;
    private Long issuanceSeq;
    private Date at;
    private byte[] chuidValue;
    private List<String> registry;
    private List<SignedVoid> voids;

    private Builder() {}

    /**
     * Enables the registry check: the SAM's (IIN, batch, allocationSeq) must be bound to its samId
     * in this root-signed registry, at the registryHead its certificate records.
     */
    public Builder registry(List<String> lines) {
      this.registry = lines == null ? null : new ArrayList<String>(lines);
      return this;
    }

    /** Enables the void check: the F9 OPID must not be voided by the SAM. */
    public Builder voids(List<SignedVoid> entries) {
      this.voids = entries == null ? null : new ArrayList<SignedVoid>(entries);
      return this;
    }

    /** Trust anchor (root) certificate. Required. */
    public Builder anchor(X509Certificate certificate) {
      return anchor(encoded(certificate));
    }

    /** Trust anchor (root) certificate as its exact encoding. Required. */
    public Builder anchor(byte[] der) {
      this.anchor = clone(der);
      return this;
    }

    public Builder samCertificate(X509Certificate certificate) {
      return samCertificate(encoded(certificate));
    }

    public Builder samCertificate(byte[] der) {
      this.samCertificate = clone(der);
      return this;
    }

    public Builder f9Certificate(X509Certificate certificate) {
      return f9Certificate(encoded(certificate));
    }

    public Builder f9Certificate(byte[] der) {
      this.f9Certificate = clone(der);
      return this;
    }

    public Builder leaf(X509Certificate certificate) {
      return leaf(encoded(certificate));
    }

    public Builder leaf(byte[] der) {
      this.leaf = clone(der);
      return this;
    }

    /** Certificate stored in the attested slot; its SPKI must equal the leaf SPKI. */
    public Builder slotCertificate(X509Certificate certificate) {
      return slotCertificate(encoded(certificate));
    }

    public Builder slotCertificate(byte[] der) {
      this.slotCertificate = clone(der);
      return this;
    }

    public Builder expectOpid(Opid opid) {
      this.expectOpid = opid;
      return this;
    }

    /**
     * Enables the OPID audit: the F9 OPID must equal {@code sequence.opidAt(issuanceSeq)} where
     * issuanceSeq is read from the F9 issuance extension. The sequence carries the IIN's FF1 key.
     */
    public Builder sequence(OpidSequence opidSequence) {
      this.sequence = opidSequence;
      return this;
    }

    /** Expected issuance sequence number; must equal the F9 issuance extension value. */
    public Builder issuanceSeq(long sequence) {
      this.issuanceSeq = sequence;
      return this;
    }

    public Builder at(Date time) {
      this.at = time == null ? null : new Date(time.getTime());
      return this;
    }

    /** CHUID element list (optionally wrapped in a 0x53 data object). */
    public Builder chuidValue(byte[] value) {
      this.chuidValue = clone(value);
      return this;
    }

    /**
     * @throws IllegalArgumentException when no trust anchor was supplied
     */
    public VerificationRequest build() {
      if (anchor == null || anchor.length == 0) {
        throw new IllegalArgumentException("a trust anchor certificate is required");
      }
      return new VerificationRequest(this);
    }

    private static byte[] encoded(X509Certificate certificate) {
      if (certificate == null) {
        return null;
      }
      try {
        return certificate.getEncoded();
      } catch (CertificateEncodingException e) {
        throw new IllegalArgumentException("certificate cannot be encoded", e);
      }
    }

    private static byte[] clone(byte[] value) {
      return value == null ? null : value.clone();
    }
  }
}
