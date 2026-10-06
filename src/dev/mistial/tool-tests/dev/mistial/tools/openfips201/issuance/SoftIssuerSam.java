/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.attestation.F9SubjectNames;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.common.ByteArrays;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A software oracle of the Issuer SAM wire contract: the same entries, signatures, STATUS and F9
 * certificate profile as the applet, with fault switches for orchestration tests.
 */
public final class SoftIssuerSam implements SamClient {
  private static final SecureRandom RANDOM = new SecureRandom();

  public final SamParameters parameters;
  public final KeyPair key = IssuanceTestKeys.p256();
  public final byte[] certificate;
  private final IssuanceTestKeys.TestRoot root;
  private final OpidSequence sequence;
  private final long allocationSeq;
  private final byte[] registryHead;
  private final X500Name samSubject;
  private final X500Name f9Template;
  private final byte[] ski;

  /** {@link SamStatus#LC_OPERATIONAL}, {@link SamStatus#LC_CLOSED} or terminated. */
  public byte lifecycle = SamStatus.LC_OPERATIONAL;

  public long issued;
  public long quota;
  public long eventSeq;
  public long lastTopUpTs;
  private byte[] head = new byte[32];
  private byte[] lastEntry;
  private byte[] nonce;

  /** ISSUE returns this status word before committing, when non-zero. */
  public int rejectIssueWith;

  /** ISSUE commits and then fails with 6500. */
  public boolean failAfterCommit;

  /** ISSUE certifies an OPID one step ahead of the sequence. */
  public boolean skipOpid;

  /** Number of APDU-level calls made. */
  public int calls;

  /**
   * @param sequence the batch's OPID sequence ({@code parameters} with the IIN FF1 key)
   * @param allocationSeq the registry allocate line's seq, certified in the batch extension
   * @param registryHead the registry head after the bind line, certified in the batch extension
   */
  public SoftIssuerSam(
      IssuanceTestKeys.TestRoot root,
      SamParameters parameters,
      OpidSequence sequence,
      long allocationSeq,
      byte[] registryHead,
      X500Name samSubject,
      X500Name f9Template)
      throws Exception {
    this.root = root;
    this.parameters = parameters;
    this.sequence = sequence;
    this.allocationSeq = allocationSeq;
    this.registryHead = registryHead.clone();
    this.samSubject = samSubject;
    this.f9Template = f9Template;
    this.ski = KeyIdentifiers.ski(key.getPublic());
    this.certificate =
        SamCertificateFactory.issue(
            root,
            IssuanceCrypto.point(key.getPublic()),
            samSubject,
            parameters.encodeBatchExtension(allocationSeq, registryHead),
            3650,
            new Date());
    this.quota = parameters.initialQuota;
    this.lastTopUpTs = parameters.initialTimestamp;
  }

  /** LOCK: commits and returns the signed genesis entry {@code 71 entry 72 sig}. */
  @Override
  public byte[] lock() {
    calls++;
    byte[] payload =
        ByteArrays.concat(
            IssuanceCrypto.sha256(certificate),
            parameters.paramsDigest(),
            IssuanceCrypto.unsigned(quota, 4),
            IssuanceCrypto.unsigned(lastTopUpTs, 8));
    return commit(SamLedgerEntry.TYPE_GENESIS, payload);
  }

  private byte[] entry(int type, byte[] payload) {
    return ByteArrays.concat(
        SamLedgerEntry.PREFIX,
        new byte[] {(byte) type},
        ski,
        IssuanceCrypto.unsigned(eventSeq + 1, 4),
        head,
        payload);
  }

  private byte[] commit(int type, byte[] payload) {
    byte[] entry = entry(type, payload);
    eventSeq++;
    head = IssuanceCrypto.sha256(entry);
    lastEntry = entry;
    return signedLast();
  }

  private byte[] signedLast() {
    return ByteArrays.concat(
        BerTlvWriter.encode(0x71, lastEntry), BerTlvWriter.encode(0x72, sign(lastEntry)));
  }

  private byte[] sign(byte[] message) {
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(key.getPrivate());
      signature.update(message);
      return signature.sign();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public PublicKey publicKey() {
    return key.getPublic();
  }

  @Override
  public SamStatus status() {
    calls++;
    return SamStatus.parse(statusTlv());
  }

  private byte[] statusTlv() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    BerTlvWriter.append(out, 0x80, new byte[] {lifecycle});
    BerTlvWriter.append(
        out, 0x82, String.format("%04d", parameters.iin).getBytes(StandardCharsets.US_ASCII));
    BerTlvWriter.append(
        out, 0x83, String.format("%04d", parameters.batch).getBytes(StandardCharsets.US_ASCII));
    BerTlvWriter.append(out, 0x85, IssuanceCrypto.unsigned(issued, 4));
    BerTlvWriter.append(out, 0x86, IssuanceCrypto.unsigned(quota, 4));
    BerTlvWriter.append(out, 0x87, IssuanceCrypto.unsigned(parameters.lcg.m, 4));
    BerTlvWriter.append(out, 0x88, IssuanceCrypto.unsigned(lastTopUpTs, 8));
    BerTlvWriter.append(out, 0x89, IssuanceCrypto.unsigned(eventSeq, 4));
    BerTlvWriter.append(out, 0x8A, head);
    BerTlvWriter.append(out, 0x8B, ski);
    BerTlvWriter.append(out, 0x8C, new byte[] {1, 5});
    BerTlvWriter.append(out, 0x8F, IssuanceCrypto.unsigned(allocationSeq, 4));
    BerTlvWriter.append(out, 0x90, registryHead);
    return out.toByteArray();
  }

  @Override
  public byte[] signedStatus(byte[] statusNonce) {
    calls++;
    byte[] status = statusTlv();
    return ByteArrays.concat(
        status,
        BerTlvWriter.encode(
            0x9E, sign(ByteArrays.concat(SamStatus.PREFIX_STATUS, statusNonce, status))));
  }

  @Override
  public byte[] beginIssuance() {
    calls++;
    if (lifecycle != SamStatus.LC_OPERATIONAL) {
      throw new SamApduException("BEGIN ISSUANCE", 0x6985);
    }
    if (issued >= quota) {
      throw new SamApduException("BEGIN ISSUANCE", SamApduException.SW_EXHAUSTED);
    }
    nonce = new byte[32];
    RANDOM.nextBytes(nonce);
    return nonce.clone();
  }

  @Override
  public byte[] issue(
      byte[] f9Point, byte[] pop, byte[] validityDer, byte[] capSha256, byte[] cplcSha256) {
    calls++;
    byte[] current = nonce;
    nonce = null;
    if (current == null) {
      throw new SamApduException("ISSUE", 0x6985);
    }
    if (capSha256 == null
        || capSha256.length != 32
        || cplcSha256 == null
        || cplcSha256.length != 32) {
      throw new SamApduException("ISSUE", 0x6A80);
    }
    if (rejectIssueWith != 0) {
      throw new SamApduException("ISSUE", rejectIssueWith);
    }
    PublicKey f9 = IssuanceCrypto.publicKey(f9Point);
    if (!IssuanceCrypto.verify(
        f9, ByteArrays.concat(CardIssuanceOrchestrator.PREFIX_POP, current, f9Point), pop)) {
      throw new SamApduException("ISSUE", SamApduException.SW_VERIFICATION_FAILED);
    }
    if (issued >= quota) {
      throw new SamApduException("ISSUE", SamApduException.SW_EXHAUSTED);
    }
    try {
      long seq = issued + 1;
      Opid opid = sequence.opidAt(skipOpid ? seq + 1 : seq);
      ASN1Sequence validity = ASN1Sequence.getInstance(validityDer);
      byte[] f9Ski = KeyIdentifiers.ski(f9);
      byte[] serial = new byte[16];
      RANDOM.nextBytes(serial);
      serial[0] = (byte) ((serial[0] & 0x7F) | 0x01);
      X509v3CertificateBuilder builder =
          new X509v3CertificateBuilder(
              samSubject,
              new BigInteger(serial),
              Time.getInstance(validity.getObjectAt(0)),
              Time.getInstance(validity.getObjectAt(1)),
              F9SubjectNames.withOpid(f9Template, opid),
              SubjectPublicKeyInfo.getInstance(f9.getEncoded()));
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
      builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(f9Ski));
      builder.addExtension(
          Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(ski));
      builder.addExtension(
          OpenPhysicalExtensions.F9_ISSUANCE,
          false,
          new DERSequence(
              new org.bouncycastle.asn1.ASN1Encodable[] {
                new ASN1Integer(OpenPhysicalExtensions.F9_ISSUANCE_VERSION),
                new ASN1Integer(seq),
                new ASN1Integer(eventSeq + 1),
                new DEROctetString(head),
                new DEROctetString(capSha256),
                new DEROctetString(cplcSha256)
              }));
      byte[] cert =
          builder
              .build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate()))
              .getEncoded();
      byte[] tbsHash =
          IssuanceCrypto.sha256(
              Certificate.getInstance(cert).getTBSCertificate().getEncoded(ASN1Encoding.DER));
      byte[] printed = opid.toPrinted().getBytes(StandardCharsets.US_ASCII);
      byte[] payload =
          ByteArrays.concat(
              IssuanceCrypto.unsigned(seq, 4),
              new byte[] {(byte) printed.length},
              printed,
              f9Ski,
              capSha256,
              cplcSha256,
              tbsHash);
      issued = seq;
      byte[] signed = commit(SamLedgerEntry.TYPE_ISSUE, payload);
      if (failAfterCommit) {
        throw new SamApduException("ISSUE", SamApduException.SW_FAILURE_AFTER_COMMIT);
      }
      return ByteArrays.concat(BerTlvWriter.encode(0x70, cert), signed);
    } catch (SamApduException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Signs a top-up with the test root, as {@code root sign-top-up} would. */
  public byte[] rootTopUpSignature(long timestamp, long add) throws Exception {
    return root.sign(
        "SHA256withECDSA",
        ByteArrays.concat(
            TopUpAuthorization.PREFIX,
            ski,
            IssuanceCrypto.unsigned(timestamp, 8),
            IssuanceCrypto.unsigned(add, 4)));
  }

  @Override
  public byte[] topUp(long timestamp, long add, byte[] rootSignature) {
    calls++;
    byte[] message =
        ByteArrays.concat(
            TopUpAuthorization.PREFIX,
            ski,
            IssuanceCrypto.unsigned(timestamp, 8),
            IssuanceCrypto.unsigned(add, 4));
    if (lifecycle != SamStatus.LC_OPERATIONAL) {
      throw new SamApduException("TOP UP", 0x6985);
    }
    if (!IssuanceCrypto.verify(root.publicKey(), message, rootSignature)) {
      throw new SamApduException("TOP UP", SamApduException.SW_VERIFICATION_FAILED);
    }
    if (timestamp <= lastTopUpTs) {
      throw new SamApduException("TOP UP", 0x6985);
    }
    quota += add;
    lastTopUpTs = timestamp;
    return commit(
        SamLedgerEntry.TYPE_TOPUP,
        ByteArrays.concat(
            IssuanceCrypto.unsigned(timestamp, 8),
            IssuanceCrypto.unsigned(add, 4),
            IssuanceCrypto.unsigned(quota, 4)));
  }

  @Override
  public byte[] samCertificate() {
    calls++;
    return certificate.clone();
  }

  @Override
  public byte[] lastEntry() {
    calls++;
    return signedLast();
  }

  @Override
  public byte[] parameters() {
    calls++;
    return BerTlvWriter.encode(0x93, parameters.paramsDigest());
  }

  @Override
  public DecipherResult decipher(String opid) {
    calls++;
    OpidSequence.Deciphered host = sequence.decrypt(Opid.parseCanonical(opid));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    BerTlvWriter.append(
        out, 0x81, String.format("%04d", host.batch).getBytes(StandardCharsets.US_ASCII));
    BerTlvWriter.append(out, 0x82, new byte[] {(byte) (host.sameBatch ? 1 : 0)});
    if (host.sameBatch) {
      BerTlvWriter.append(out, 0x83, IssuanceCrypto.unsigned(host.count, 4));
      BerTlvWriter.append(out, 0x84, new byte[] {(byte) (host.issuedWithin(issued) ? 1 : 0)});
    }
    return DecipherResult.parse(out.toByteArray());
  }

  @Override
  public byte[] terminate() {
    calls++;
    terminated = true;
    lifecycle = SamStatus.LC_TERMINATED;
    return commit(
        SamLedgerEntry.TYPE_TERMINATE,
        ByteArrays.concat(IssuanceCrypto.unsigned(issued, 4), IssuanceCrypto.unsigned(quota, 4)));
  }

  /** Whether TERMINATE was sent. */
  public boolean terminated;

  /** CLOSE: OPERATIONAL only; the SAM then refuses BEGIN ISSUANCE, ISSUE and TOP UP. */
  @Override
  public byte[] close() {
    calls++;
    if (lifecycle != SamStatus.LC_OPERATIONAL) {
      throw new SamApduException("CLOSE", 0x6985);
    }
    lifecycle = SamStatus.LC_CLOSED;
    return commit(
        SamLedgerEntry.TYPE_CLOSE,
        ByteArrays.concat(IssuanceCrypto.unsigned(issued, 4), IssuanceCrypto.unsigned(quota, 4)));
  }

  /** VOID: {@code 1 <= seq <= issued}, otherwise 6A80; the SAM recomputes OPID_seq itself. */
  @Override
  public byte[] voidIssuance(long seq, int reason) {
    calls++;
    if (seq < 1 || seq > issued) {
      throw new SamApduException("VOID", 0x6A80);
    }
    byte[] printed = sequence.opidAt(seq).toPrinted().getBytes(StandardCharsets.US_ASCII);
    return commit(
        SamLedgerEntry.TYPE_VOID,
        ByteArrays.concat(
            IssuanceCrypto.unsigned(seq, 4),
            new byte[] {(byte) printed.length},
            printed,
            new byte[] {(byte) reason}));
  }

  @Override
  public void changeOperatorPin(byte[] oldPin, byte[] newPin) {
    calls++;
  }

  @Override
  public byte[] generateTransportKey() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void putParameters(byte[] parametersDer) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setOperatorPin(byte[] pin) {
    throw new UnsupportedOperationException();
  }

  @Override
  public byte[] generateKey() {
    throw new UnsupportedOperationException();
  }

  @Override
  public byte[] loadCertificate(byte[] cert) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void verifyPin(byte[] pin) {
    calls++;
  }

  public byte[] head() {
    return Arrays.copyOf(head, head.length);
  }
}
