/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions;
import dev.mistial.tools.openfips201.opid.Lcg;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * The batch identity and OPID sequence provisioned into a SAM at the root station, and its two
 * encodings: the PUT PARAMETERS v5 packet and the root-signed SAM batch extension v3.
 *
 * <pre>
 * IssuerSamParameters ::= SEQUENCE {
 *   type OBJECT IDENTIFIER   -- 1.3.6.1.4.1.57923.20.10.10.1
 *   version INTEGER (5),
 *   issue [16] IMPLICIT SEQUENCE { issuerId, batchNumber, initialQuota INTEGER },
 *   lcg   [17] IMPLICIT SEQUENCE { seed, modulus (10^8), multiplier, increment INTEGER },
 *   f9SubjectTemplate [20] EXPLICIT Name,
 *   samSubject        [21] EXPLICIT Name OPTIONAL,
 *   rootPublicKey     [22] IMPLICIT OCTET STRING (SIZE 65),
 *   initialTimestamp  [23] IMPLICIT OCTET STRING (SIZE 8),
 *   wrappedFpeKey     [24] IMPLICIT SEQUENCE {
 *     hostEphemeralPublicKey OCTET STRING (SIZE 65), wrappedKey OCTET STRING (SIZE 40) } }
 *
 * SamBatch ::= SEQUENCE { version INTEGER (3), issuerId, batch, initialQuota INTEGER,
 *   initialTimestamp OCTET STRING (SIZE 8), paramsDigest OCTET STRING (SIZE 32),
 *   allocationSeq INTEGER, registryHead OCTET STRING (SIZE 32) }
 * </pre>
 *
 * <p>The FF1 key never appears here in clear: the packet carries it wrapped to the SAM's one-time
 * transport key, and paramsDigest (v3) commits only to its check value.
 */
public final class SamParameters {
  public static final int PACKET_VERSION = 5;
  public static final int BATCH_EXTENSION_VERSION = 3;

  public final int iin;
  public final int batch;
  public final long initialQuota;
  public final long initialTimestamp;
  public final Lcg lcg;
  private final byte[] paramsDigest;

  /**
   * @param cipher FF1 under the IIN key, used only for the key check value in paramsDigest
   */
  public SamParameters(
      int iin, int batch, long initialQuota, long initialTimestamp, Lcg lcg, OpidCipher cipher) {
    this.iin = iin;
    this.batch = batch;
    this.initialQuota = initialQuota;
    this.initialTimestamp = initialTimestamp;
    this.lcg = lcg;
    this.paramsDigest =
        OpidSequence.of(iin, batch, lcg, cipher).paramsDigest(initialQuota, initialTimestamp);
  }

  /** {@link OpidSequence#paramsDigest} (v3) of these parameters. */
  public byte[] paramsDigest() {
    return paramsDigest.clone();
  }

  /** The PUT PARAMETERS v5 DER; {@code samSubject} may be null. */
  public byte[] encodePacket(
      X500Name f9Template, X500Name samSubject, byte[] rootPoint, RootKeys.WrappedKey wrapped) {
    ASN1EncodableVector issue = new ASN1EncodableVector();
    issue.add(new ASN1Integer(iin));
    issue.add(new ASN1Integer(batch));
    issue.add(new ASN1Integer(initialQuota));
    ASN1EncodableVector generator = new ASN1EncodableVector();
    generator.add(new ASN1Integer(lcg.x0));
    generator.add(new ASN1Integer(lcg.m));
    generator.add(new ASN1Integer(lcg.a));
    generator.add(new ASN1Integer(lcg.c));
    ASN1EncodableVector key = new ASN1EncodableVector();
    key.add(new DEROctetString(wrapped.ephemeralPublicKey()));
    key.add(new DEROctetString(wrapped.wrapped()));
    ASN1EncodableVector packet = new ASN1EncodableVector();
    packet.add(OpenPhysicalExtensions.SAM_PARAMETERS);
    packet.add(new ASN1Integer(PACKET_VERSION));
    packet.add(new DERTaggedObject(false, 16, new DERSequence(issue)));
    packet.add(new DERTaggedObject(false, 17, new DERSequence(generator)));
    packet.add(new DERTaggedObject(true, 20, f9Template));
    if (samSubject != null) {
      packet.add(new DERTaggedObject(true, 21, samSubject));
    }
    packet.add(new DERTaggedObject(false, 22, new DEROctetString(rootPoint)));
    packet.add(
        new DERTaggedObject(
            false, 23, new DEROctetString(IssuanceCrypto.unsigned(initialTimestamp, 8))));
    packet.add(new DERTaggedObject(false, 24, new DERSequence(key)));
    return der(new DERSequence(packet));
  }

  /** The SAM batch extension value (v3), committing to the registry allocation and head. */
  public byte[] encodeBatchExtension(long allocationSeq, byte[] registryHead) {
    ASN1EncodableVector value = new ASN1EncodableVector();
    value.add(new ASN1Integer(BATCH_EXTENSION_VERSION));
    value.add(new ASN1Integer(iin));
    value.add(new ASN1Integer(batch));
    value.add(new ASN1Integer(initialQuota));
    value.add(new DEROctetString(IssuanceCrypto.unsigned(initialTimestamp, 8)));
    value.add(new DEROctetString(paramsDigest));
    value.add(new ASN1Integer(allocationSeq));
    value.add(new DEROctetString(registryHead));
    return der(new DERSequence(value));
  }

  private static byte[] der(DERSequence sequence) {
    try {
      return sequence.getEncoded(ASN1Encoding.DER);
    } catch (IOException e) {
      throw new IllegalStateException("DER encoding failed", e);
    }
  }
}
