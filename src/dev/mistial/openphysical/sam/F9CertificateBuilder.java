/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
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

package dev.mistial.openphysical.sam;

/**
 * Builds the card F9 attestation-authority certificate inside the {@code 70} response frame.
 *
 * <p>Profile (RFC 5280 Section 4.1): v3; random positive 16-octet serial; ecdsa-with-SHA256; issuer
 * = the SAM subject as exact DER from the stored SAM certificate; validity as requested by the
 * host; subject = provisioned template RDNs followed by a final {@code serialNumber} (2.5.4.5,
 * PrintableString) RDN holding the OPID; SPKI id-ecPublicKey/prime256v1. Extensions, in order:
 * BasicConstraints critical {@code 30 06 01 01 FF 02 01 00}; KeyUsage critical {@code 03 02 02 04}
 * (keyCertSign); SubjectKeyIdentifier (RFC 7093 method 1); AuthorityKeyIdentifier keyIdentifier =
 * SAM SKI; issuance extension 1.3.6.1.4.1.57923.20.10.10.2 (non-critical) {@code SEQUENCE{version
 * 2, issuanceSeq, eventSeq, prevChainHead OCTET STRING(32), capSha256 OCTET STRING(32), cplcSha256
 * OCTET STRING(32)}}. The PIV card checks BC, KU and SKI exactly and requires a well-formed AKI.
 * The worst case (128-octet SAM subject, 96-octet template, GeneralizedTime validity, 5-octet
 * eventSeq, 72-octet signature) is 756 octets, inside the card's 760-octet limit.
 */
final class F9CertificateBuilder {
  private F9CertificateBuilder() {}

  /**
   * Opens {@code 70 { Certificate { ...} }} and writes the complete TBSCertificate.
   *
   * <p>On return the writer has two open structures (70 and Certificate) and the TBS occupies
   * {@code [tbsOffset, writer.getOffset())} with its final DER length.
   *
   * @return the offset of the TBSCertificate's first octet
   */
  static short beginAndWriteTbs(
      DERWriter writer,
      byte[] out,
      SamState state,
      byte[] serial,
      short serialOffset,
      byte[] validity,
      short validityOffset,
      short validityLength,
      byte[] opid,
      short opidOffset,
      short opidLength,
      byte[] point,
      short pointOffset,
      byte[] f9Ski,
      short f9SkiOffset,
      byte[] issuanceSeq,
      short issuanceSeqOffset,
      byte[] eventSeq,
      short eventSeqOffset,
      byte[] measurements,
      short capSha256Offset,
      short cplcSha256Offset) {
    writer.init(out, (short) 0);
    writer.begin((byte) 0x70);
    writer.begin((byte) 0x30); // Certificate
    short tbsOffset = writer.getOffset();
    writer.begin((byte) 0x30); // TBSCertificate
    writer.write(SamConst.DER_VERSION_V3, (short) 0, (short) SamConst.DER_VERSION_V3.length);
    writer.writePositiveInteger(serial, serialOffset, SamConst.LENGTH_SERIAL);
    writer.write(
        SamConst.DER_ECDSA_WITH_SHA256, (short) 0, (short) SamConst.DER_ECDSA_WITH_SHA256.length);
    writer.write(state.samCert, state.samSubjectOffset, state.samSubjectLength);
    writer.write(validity, validityOffset, validityLength);

    writer.begin((byte) 0x30); // subject
    writer.write(state.f9SubjectTemplate, (short) 0, state.f9SubjectTemplateLength);
    writer.begin((byte) 0x31);
    writer.begin((byte) 0x30);
    writer.writeTlv(
        TLV.ASN1_OBJECT,
        SamConst.OID_SERIAL_NUMBER,
        (short) 0,
        (short) SamConst.OID_SERIAL_NUMBER.length);
    writer.writeTlv(TLV.ASN1_PRINT_STRING, opid, opidOffset, opidLength);
    writer.end();
    writer.end();
    writer.end();

    writer.write(
        SamConst.DER_SPKI_P256_PREFIX, (short) 0, (short) SamConst.DER_SPKI_P256_PREFIX.length);
    writer.write(point, pointOffset, SamConst.LENGTH_POINT);

    writer.begin((byte) 0xA3);
    writer.begin((byte) 0x30);
    writer.write(
        SamConst.DER_F9_BASIC_CONSTRAINTS,
        (short) 0,
        (short) SamConst.DER_F9_BASIC_CONSTRAINTS.length);
    writer.write(SamConst.DER_F9_KEY_USAGE, (short) 0, (short) SamConst.DER_F9_KEY_USAGE.length);
    writer.write(SamConst.DER_SKI_PREFIX, (short) 0, (short) SamConst.DER_SKI_PREFIX.length);
    writer.write(f9Ski, f9SkiOffset, SamConst.LENGTH_SKI);
    writer.write(SamConst.DER_AKI_PREFIX, (short) 0, (short) SamConst.DER_AKI_PREFIX.length);
    writer.write(state.samSki, (short) 0, SamConst.LENGTH_SKI);
    writer.begin((byte) 0x30); // issuance extension
    writer.writeTlv(
        TLV.ASN1_OBJECT,
        SamConst.OID_ISSUANCE_EXTENSION,
        (short) 0,
        (short) SamConst.OID_ISSUANCE_EXTENSION.length);
    writer.begin(TLV.ASN1_OCTET_STRING);
    writer.begin((byte) 0x30);
    writer.writeIntegerByte(SamConst.ISSUANCE_EXTENSION_VERSION);
    writer.writePositiveInteger(issuanceSeq, issuanceSeqOffset, SamConst.LENGTH_U32);
    writer.writePositiveInteger(eventSeq, eventSeqOffset, SamConst.LENGTH_U32);
    writer.writeTlv(TLV.ASN1_OCTET_STRING, state.chainHead, (short) 0, SamConst.LENGTH_HASH);
    writer.writeTlv(TLV.ASN1_OCTET_STRING, measurements, capSha256Offset, SamConst.LENGTH_HASH);
    writer.writeTlv(TLV.ASN1_OCTET_STRING, measurements, cplcSha256Offset, SamConst.LENGTH_HASH);
    writer.end();
    writer.end();
    writer.end();
    writer.end();
    writer.end();

    writer.end(); // TBSCertificate
    return tbsOffset;
  }

  /**
   * Appends signatureAlgorithm and signatureValue and closes the Certificate and {@code 70}.
   *
   * @return the offset following the {@code 70} frame
   */
  static short finish(DERWriter writer, byte[] signature, short signatureOffset, short length) {
    writer.write(
        SamConst.DER_ECDSA_WITH_SHA256, (short) 0, (short) SamConst.DER_ECDSA_WITH_SHA256.length);
    writer.write(TLV.ASN1_BIT_STRING);
    writer.writeLength((short) (length + 1));
    writer.write((byte) 0x00);
    writer.write(signature, signatureOffset, length);
    writer.end(); // Certificate
    writer.end(); // 70
    return writer.getOffset();
  }
}
