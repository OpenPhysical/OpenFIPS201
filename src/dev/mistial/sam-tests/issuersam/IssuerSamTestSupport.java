package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertEquals;

import apdu4j.core.BIBO;
import dev.mistial.openphysical.sam.IssuerSam;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.function.Supplier;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/**
 * Shared harness for end-to-end issuer SAM tests: installs the SAM into jCardEngine, provides a
 * BouncyCastle stand-in for the root (HSM), and drives personalization and issuance with raw APDUs.
 *
 * <p>Secure-channel commands run inside {@link #withMockedScp}, which supplies an authenticated
 * GlobalPlatform session whose unwrap is the identity, mirroring the PIV test harness.
 */
abstract class IssuerSamTestSupport {
  static final byte[] SAM_PACKAGE_AID_BYTES = hex("F04F50454E50485953414D");
  static final byte[] SAM_AID_BYTES = hex("F04F50454E50485953414D0001000000");
  static final AID SAM_AID = new AID(SAM_AID_BYTES, (short) 0, (byte) SAM_AID_BYTES.length);
  static final byte[] PIN = "13572468".getBytes();
  static final long INITIAL_TS = 1_790_000_000_000L;

  static final byte LC_INSTALLED = (byte) 0x5A;
  static final byte LC_PARAMS_SET = (byte) 0x69;
  static final byte LC_KEY_GENERATED = (byte) 0x96;
  static final byte LC_CERT_LOADED = (byte) 0xA5;
  static final byte LC_OPERATIONAL = (byte) 0xC3;
  static final byte LC_TERMINATED = (byte) 0x3C;

  protected JavaCardEngine engine;
  protected BIBO session;
  protected TestRoot root;

  @BeforeEach
  void setUpSam() throws Exception {
    root = new TestRoot();
    engine = createEngine();
    installApplet();
    session = engine.connect();
  }

  @AfterEach
  void tearDownSam() {
    if (session != null) session.close();
  }

  protected JavaCardEngine createEngine() {
    return JavaCardEngine.create();
  }

  protected void installApplet() {
    engine.installApplet(SAM_AID, IssuerSam.class, new byte[0]);
  }

  //
  // Transport.
  //

  ResponseAPDU selectSam() {
    return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, SAM_AID_BYTES, 256));
  }

  ResponseAPDU transmit(CommandAPDU command) {
    return new ResponseAPDU(session.transceive(command.getBytes()));
  }

  ResponseAPDU transmit(int cla, int ins, int p1, int p2) {
    return transmit(new CommandAPDU(cla, ins, p1, p2, 256));
  }

  ResponseAPDU transmit(int cla, int ins, int p1, int p2, byte[] data) {
    return transmit(new CommandAPDU(cla, ins, p1, p2, data, 256));
  }

  /** Sends data with ISO command chaining in frames of at most 200 octets. */
  ResponseAPDU transmitChained(int cla, int ins, int p1, int p2, byte[] data) {
    int offset = 0;
    while (data.length - offset > 200) {
      ResponseAPDU frame =
          transmit(
              new CommandAPDU(
                  cla | 0x10, ins, p1, p2, Arrays.copyOfRange(data, offset, offset + 200)));
      if (frame.getSW() != 0x9000) return frame;
      offset += 200;
    }
    return transmit(cla, ins, p1, p2, Arrays.copyOfRange(data, offset, data.length));
  }

  /** Collects a 61xx response chain with plaintext GET RESPONSE. */
  byte[] collect(ResponseAPDU response, String context) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      output.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    output.write(current.getData(), 0, current.getData().length);
    return output.toByteArray();
  }

  static void assertSw(int expected, ResponseAPDU response, String context) {
    assertEquals(
        expected & 0xFFFF,
        response.getSW(),
        context
            + ": expected "
            + Integer.toHexString(expected & 0xFFFF)
            + " got "
            + Integer.toHexString(response.getSW()));
  }

  <T> T withMockedScp(Supplier<T> action) {
    try (MockedStatic<GPSystem> mockedGp = Mockito.mockStatic(GPSystem.class)) {
      Mockito.when(GPSystem.getCardContentState()).thenReturn(GPSystem.APPLICATION_SELECTABLE);
      SecureChannel secureChannel = Mockito.mock(SecureChannel.class);
      Mockito.when(secureChannel.getSecurityLevel())
          .thenReturn(
              (byte)
                  (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION | SecureChannel.C_MAC));
      Mockito.when(
              secureChannel.unwrap(
                  Mockito.any(byte[].class), Mockito.anyShort(), Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      Mockito.when(GPSystem.getSecureChannel()).thenReturn(secureChannel);
      return action.get();
    }
  }

  void withMockedScp(Runnable action) {
    withMockedScp(
        () -> {
          action.run();
          return null;
        });
  }

  //
  // Status.
  //

  byte[] status() {
    return collect(transmit(0x80, 0xCA, 0x00, 0x01), "GET DATA STATUS");
  }

  byte lifecycle() {
    return tlvValue(status(), 0x80)[0];
  }

  long issued() {
    return new BigInteger(1, tlvValue(status(), 0x85)).longValue();
  }

  byte[] chainHead() {
    return tlvValue(status(), 0x8A);
  }

  //
  // Personalization.
  //

  /** Personalizes and locks the SAM; returns the genesis response (71 entry, 72 sig). */
  byte[] personalize(Params params) {
    return withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x9000, putParameters(params), "PUT PARAMETERS");
          assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "SET OPERATOR PIN");
          byte[] point = generateKey();
          byte[] cert = root.issueSamCertificate(point, params, new SamCertSpec());
          ResponseAPDU loaded = transmitChained(0x84, 0xD4, 0x00, 0x00, cert);
          assertSw(0x9000, loaded, "LOAD SAM CERTIFICATE");
          return collect(transmit(0x84, 0xD6, 0x00, 0x00), "LOCK");
        });
  }

  /**
   * GENERATE TRANSPORT KEY then PUT PARAMETERS v5 with the FF1 key wrapped to it. Returns the first
   * failing response. Caller holds the mocked SCP.
   */
  ResponseAPDU putParameters(Params params) {
    ResponseAPDU transport = transmit(0x84, 0x4A, 0x00, 0x00);
    if (transport.getSW() != 0x9000) return transport;
    params.transportPub = Arrays.copyOfRange(transport.getData(), 2, 67);
    return transmitChained(0x84, 0xD0, 0x00, 0x00, params.encode());
  }

  /** GENERATE TRANSPORT KEY then PUT PARAMETERS with a raw packet. */
  ResponseAPDU putRawParameters(byte[] packet) {
    assertSw(0x9000, transmit(0x84, 0x4A, 0x00, 0x00), "GENERATE TRANSPORT KEY");
    return transmitChained(0x84, 0xD0, 0x00, 0x00, packet);
  }

  /**
   * Host side of the transport: Z = ECDH(hostEph, transportPub), KEK = X9.63 SHA-256 KDF with
   * SharedInfo "OPSAMKT1" | transportPub | hostEphPub | ASCII(IIN), wrapped = RFC 3394 AES-KW.
   */
  static byte[][] wrapFpeKey(byte[] transportPub, KeyPair hostEph, int iin, byte[] fpeKey) {
    try {
      javax.crypto.KeyAgreement agreement = javax.crypto.KeyAgreement.getInstance("ECDH");
      agreement.init(hostEph.getPrivate());
      agreement.doPhase(publicKey(transportPub), true);
      byte[] z = agreement.generateSecret();
      byte[] hostPub = point(hostEph.getPublic());
      byte[] kek =
          sha256(
              z,
              hex("00000001"),
              "OPSAMKT1".getBytes(),
              transportPub,
              hostPub,
              String.format("%04d", iin).getBytes());
      org.bouncycastle.crypto.engines.RFC3394WrapEngine wrap =
          new org.bouncycastle.crypto.engines.RFC3394WrapEngine(
              org.bouncycastle.crypto.engines.AESEngine.newInstance());
      wrap.init(true, new org.bouncycastle.crypto.params.KeyParameter(kek));
      return new byte[][] {hostPub, wrap.wrap(fpeKey, 0, fpeKey.length)};
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** GENERATE SAM KEY; returns the 65-octet point. Caller holds the mocked SCP. */
  byte[] generateKey() {
    byte[] response = collect(transmit(0x84, 0x46, 0x00, 0x00), "GENERATE SAM KEY");
    assertEquals((byte) 0x86, response[0]);
    assertEquals(0x41, response[1]);
    return Arrays.copyOfRange(response, 2, 67);
  }

  /** Reads the stored SAM certificate. */
  X509CertificateHolder samCertificate() throws Exception {
    return new X509CertificateHolder(collect(transmit(0x80, 0xCA, 0x00, 0x02), "GET SAM CERT"));
  }

  //
  // Issuance.
  //

  /** Result of one ISSUE: certificate, entry, entry signature, and the F9 key pair. */
  static final class Issued {
    byte[] certificate;
    byte[] entry;
    byte[] signature;
    KeyPair f9;
    byte[] raw;
  }

  /** VERIFY PIN, BEGIN ISSUANCE and ISSUE with a fresh F9 key; asserts 9000. */
  Issued issueOne() {
    return withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY PIN");
          KeyPair f9 = newP256();
          ResponseAPDU response = issueResponse(f9, beginIssuance(), defaultValidity());
          Issued issued = parseIssued(collect(response, "ISSUE"));
          issued.f9 = f9;
          return issued;
        });
  }

  byte[] beginIssuance() {
    ResponseAPDU response = transmit(0x84, 0x84, 0x00, 0x00);
    assertSw(0x9000, response, "BEGIN ISSUANCE");
    assertEquals(32, response.getData().length);
    return response.getData();
  }

  ResponseAPDU issueResponse(KeyPair f9, byte[] nonce, byte[] validity) {
    byte[] point = point(f9.getPublic());
    byte[] pop = sign(f9.getPrivate(), concat("OPF9POP".getBytes(), nonce, point));
    return transmit(0x84, 0x2A, 0x00, 0xF9, issueData(point, pop, validity));
  }

  static byte[] issueData(byte[] point, byte[] pop, byte[] validity) {
    return concat(tlv(0x86, point), tlv(0x9E, pop), tlv(0x93, validity));
  }

  static Issued parseIssued(byte[] data) {
    Issued issued = new Issued();
    issued.raw = data;
    int offset = 0;
    byte[][] values = new byte[3][];
    int[] tags = {0x70, 0x71, 0x72};
    for (int i = 0; i < 3; i++) {
      assertEquals(tags[i], data[offset] & 0xFF, "response tag " + i);
      int lengthOffset = offset + 1;
      int length = derLength(data, lengthOffset);
      int valueOffset = lengthOffset + derLengthSize(data, lengthOffset);
      values[i] = Arrays.copyOfRange(data, valueOffset, valueOffset + length);
      offset = valueOffset + length;
    }
    assertEquals(data.length, offset, "no trailing octets");
    issued.certificate = values[0];
    issued.entry = values[1];
    issued.signature = values[2];
    return issued;
  }

  /** Validity inside the SAM certificate's validity (UTCTime). */
  static byte[] defaultValidity() {
    long now = System.currentTimeMillis();
    return validity(new Date(now - 3_600_000L), new Date(now + 5L * 365 * 86_400_000L));
  }

  static byte[] validity(Date notBefore, Date notAfter) {
    try {
      return new DERSequence(
              new org.bouncycastle.asn1.ASN1Encodable[] {new Time(notBefore), new Time(notAfter)})
          .getEncoded("DER");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Splits a {@code 71 L entry 72 L sig} response. */
  static byte[][] entryAndSignature(byte[] data) {
    assertEquals(0x71, data[0] & 0xFF);
    int length = derLength(data, 1);
    int valueOffset = 1 + derLengthSize(data, 1);
    byte[] entry = Arrays.copyOfRange(data, valueOffset, valueOffset + length);
    int sigTag = valueOffset + length;
    assertEquals(0x72, data[sigTag] & 0xFF);
    int sigLength = derLength(data, sigTag + 1);
    int sigOffset = sigTag + 1 + derLengthSize(data, sigTag + 1);
    assertEquals(data.length, sigOffset + sigLength);
    return new byte[][] {entry, Arrays.copyOfRange(data, sigOffset, sigOffset + sigLength)};
  }

  //
  // Reference values.
  //

  /** Independent reference (LCG then FF1) for the parameters. */
  static OpidV2Reference reference(Params params) {
    return new OpidV2Reference(
        params.issuerId, (int) params.batch, params.a, params.c, params.x0, params.fpeKey);
  }

  /** Reference OPID for issuance n. */
  static String referenceOpid(Params params, long n) {
    return reference(params).opidAt(n);
  }

  /** Reference paramsDigest v3. */
  static byte[] referenceParamsDigest(Params params) {
    return reference(params).paramsDigest(params.quota, params.timestamp);
  }

  //
  // Crypto helpers.
  //

  static KeyPair newP256() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] point(PublicKey key) {
    ECPublicKey ec = (ECPublicKey) key;
    byte[] out = new byte[65];
    out[0] = 0x04;
    copyFixed(ec.getW().getAffineX(), out, 1);
    copyFixed(ec.getW().getAffineY(), out, 33);
    return out;
  }

  private static void copyFixed(BigInteger value, byte[] out, int offset) {
    byte[] raw = value.toByteArray();
    int length = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - length, out, offset + 32 - length, length);
  }

  static byte[] sign(PrivateKey key, byte[] message) {
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(key);
      signature.update(message);
      return signature.sign();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static boolean verify(PublicKey key, byte[] message, byte[] sig) {
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initVerify(key);
      signature.update(message);
      return signature.verify(sig);
    } catch (Exception e) {
      return false;
    }
  }

  static PublicKey publicKey(byte[] point) {
    try {
      SubjectPublicKeyInfo spki = spki(point);
      return java.security.KeyFactory.getInstance("EC")
          .generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static SubjectPublicKeyInfo spki(byte[] point) {
    return new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, X9ObjectIdentifiers.prime256v1),
        point);
  }

  static byte[] sha256(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] part : parts) digest.update(part);
      return digest.digest();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] ski(byte[] point) {
    return Arrays.copyOf(sha256(point), 20);
  }

  //
  // Parameters and the root.
  //

  /** Provisioned issuance parameters (host side of PUT PARAMETERS). */
  static final class Params {
    int issuerId = 1234;
    long batch = 9123;
    long quota = 10;
    long x0 = 12345678;
    long modulus = 100_000_000L;
    long a = 21;
    long c = 7;
    X500Name template = new X500Name("CN=OpenPhysical Card,O=OpenPhysical Test");
    X500Name samSubject = new X500Name("CN=Issuer SAM 1,O=OpenPhysical Test");
    boolean includeSamSubject = true;
    byte[] rootPoint;
    long timestamp = INITIAL_TS;
    byte[] fpeKey = hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    int version = 5;
    boolean includeFpeKey = true;
    // Batch extension v3 registry binding.
    long allocationSeq = 0x8000_0001L;
    byte[] registryHead = sha256("registry".getBytes());
    // Transport public key from GENERATE TRANSPORT KEY; a throwaway point when unset.
    byte[] transportPub;
    // Overrides for negative tests of the wrappedFpeKey field.
    byte[] hostEphOverride;
    byte[] wrappedOverride;
    Integer kdfIinOverride;

    /** Parameter set {@code index} (0..9): distinct IIN, batch, LCG and key choices. */
    static Params variant(TestRoot root, int index) {
      Params params = new Params();
      params.rootPoint = root.point;
      int[] iins = {1234, 9876, 0, 9999, 42, 1234, 5000, 1, 7777, 2468};
      int[] batches = {9123, 5, 0, 9999, 42, 1, 1234, 7, 9998, 300};
      long[] multipliers = {86_421L, 87_654_321L, 21L, 99_999_981L, 1_234_561L};
      long[] increments = {7L, 12_345_679L, 1L, 99_999_999L, 7_654_321L};
      params.issuerId = iins[index];
      params.batch = batches[index];
      params.a = multipliers[index % 5];
      params.c = increments[index % 5];
      params.x0 = (index * 11_111_111L + 31_415_926L) % 100_000_000L;
      if ((index & 1) == 1) {
        params.fpeKey = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
      }
      return params;
    }

    long m() {
      return modulus;
    }

    byte[] encode() {
      try {
        ASN1EncodableVector issue = new ASN1EncodableVector();
        issue.add(new ASN1Integer(issuerId));
        issue.add(new ASN1Integer(batch));
        issue.add(new ASN1Integer(quota));
        ASN1EncodableVector lcg = new ASN1EncodableVector();
        lcg.add(new ASN1Integer(x0));
        lcg.add(new ASN1Integer(m()));
        lcg.add(new ASN1Integer(a));
        lcg.add(new ASN1Integer(c));
        ASN1EncodableVector packet = new ASN1EncodableVector();
        packet.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.1"));
        packet.add(new ASN1Integer(version));
        packet.add(new DERTaggedObject(false, 16, new DERSequence(issue)));
        packet.add(new DERTaggedObject(false, 17, new DERSequence(lcg)));
        packet.add(new DERTaggedObject(true, 20, template));
        if (includeSamSubject) packet.add(new DERTaggedObject(true, 21, samSubject));
        packet.add(new DERTaggedObject(false, 22, new DEROctetString(rootPoint)));
        packet.add(new DERTaggedObject(false, 23, new DEROctetString(u64(timestamp))));
        if (includeFpeKey) {
          byte[] target = transportPub != null ? transportPub : point(newP256().getPublic());
          int kdfIin = kdfIinOverride != null ? kdfIinOverride : issuerId;
          byte[][] wrapped = wrapFpeKey(target, newP256(), kdfIin, fpeKey);
          ASN1EncodableVector field = new ASN1EncodableVector();
          field.add(new DEROctetString(hostEphOverride != null ? hostEphOverride : wrapped[0]));
          field.add(new DEROctetString(wrappedOverride != null ? wrappedOverride : wrapped[1]));
          packet.add(new DERTaggedObject(false, 24, new DERSequence(field)));
        }
        return new DERSequence(packet).getEncoded("DER");
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
  }

  /** SAM certificate profile knobs for negative tests. */
  static final class SamCertSpec {
    Integer pathLen = 1;
    boolean basicConstraintsCritical = true;
    boolean includeKeyUsage = true;
    int keyUsage = KeyUsage.keyCertSign;
    boolean includeSki = true;
    byte[] skiOverride;
    boolean includeBatch = true;
    byte[] batchOverride;
    boolean duplicateSki;
    boolean unknownCritical;
    X500Name subjectOverride;
    Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
    Date notAfter = new Date(System.currentTimeMillis() + 10L * 365 * 86_400_000L);
    KeyPair signerOverride;
    byte[] pointOverride;
  }

  /** BouncyCastle stand-in for the root CA (HSM). */
  static final class TestRoot {
    final KeyPair keyPair = newP256();
    final byte[] point = point(keyPair.getPublic());
    final X500Name name = new X500Name("CN=OpenPhysical Test Root,O=OpenPhysical Test");
    final X509CertificateHolder certificate;

    TestRoot() throws Exception {
      long now = System.currentTimeMillis();
      X509v3CertificateBuilder builder =
          new X509v3CertificateBuilder(
              name,
              BigInteger.ONE,
              new Date(now - 2 * 86_400_000L),
              new Date(now + 20L * 365 * 86_400_000L),
              name,
              spki(point));
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      builder.addExtension(
          Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      builder.addExtension(Extension.subjectKeyIdentifier, false, new DEROctetString(ski(point)));
      certificate = builder.build(signer(keyPair));
    }

    static ContentSigner signer(KeyPair keyPair) throws Exception {
      return new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
    }

    byte[] batchExtension(Params params) throws Exception {
      ASN1EncodableVector batch = new ASN1EncodableVector();
      batch.add(new ASN1Integer(3));
      batch.add(new ASN1Integer(params.issuerId));
      batch.add(new ASN1Integer(params.batch));
      batch.add(new ASN1Integer(params.quota));
      batch.add(new DEROctetString(u64(params.timestamp)));
      batch.add(new DEROctetString(referenceParamsDigest(params)));
      batch.add(new ASN1Integer(params.allocationSeq));
      batch.add(new DEROctetString(params.registryHead));
      return new DERSequence(batch).getEncoded("DER");
    }

    byte[] issueSamCertificate(byte[] samPoint, Params params, SamCertSpec spec) {
      try {
        byte[] subjectPoint = spec.pointOverride != null ? spec.pointOverride : samPoint;
        X500Name subject = spec.subjectOverride != null ? spec.subjectOverride : params.samSubject;
        X509v3CertificateBuilder builder =
            new X509v3CertificateBuilder(
                name,
                new BigInteger(64, new java.security.SecureRandom()).setBit(62),
                spec.notBefore,
                spec.notAfter,
                subject,
                spki(subjectPoint));
        if (spec.pathLen != null) {
          builder.addExtension(
              Extension.basicConstraints,
              spec.basicConstraintsCritical,
              new BasicConstraints(spec.pathLen));
        }
        if (spec.includeKeyUsage) {
          builder.addExtension(Extension.keyUsage, true, new KeyUsage(spec.keyUsage));
        }
        if (spec.includeSki) {
          byte[] id = spec.skiOverride != null ? spec.skiOverride : ski(subjectPoint);
          builder.addExtension(Extension.subjectKeyIdentifier, false, new DEROctetString(id));
        }
        builder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            new DERSequence(new DERTaggedObject(false, 0, new DEROctetString(ski(point)))));
        if (spec.includeBatch) {
          byte[] value = spec.batchOverride != null ? spec.batchOverride : batchExtension(params);
          builder.addExtension(
              new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.3"),
              false,
              org.bouncycastle.asn1.ASN1Primitive.fromByteArray(value));
        }
        if (spec.unknownCritical) {
          builder.addExtension(
              new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.99"), true, new DERSequence());
        }
        KeyPair signer = spec.signerOverride != null ? spec.signerOverride : keyPair;
        byte[] encoded = builder.build(signer(signer)).getEncoded();
        if (spec.duplicateSki) encoded = duplicateFirstExtension(encoded, signer);
        return encoded;
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }

    /** Re-signs a certificate whose extension list repeats its last extension. */
    private static byte[] duplicateFirstExtension(byte[] encoded, KeyPair signer) throws Exception {
      org.bouncycastle.asn1.x509.Certificate cert =
          org.bouncycastle.asn1.x509.Certificate.getInstance(encoded);
      org.bouncycastle.asn1.x509.TBSCertificate tbs = cert.getTBSCertificate();
      org.bouncycastle.asn1.ASN1Sequence tbsSeq =
          org.bouncycastle.asn1.ASN1Sequence.getInstance(tbs.toASN1Primitive());
      ASN1EncodableVector fields = new ASN1EncodableVector();
      for (int i = 0; i < tbsSeq.size(); i++) {
        org.bouncycastle.asn1.ASN1Encodable field = tbsSeq.getObjectAt(i);
        if (field instanceof org.bouncycastle.asn1.ASN1TaggedObject
            && ((org.bouncycastle.asn1.ASN1TaggedObject) field).getTagNo() == 3) {
          org.bouncycastle.asn1.ASN1Sequence list =
              org.bouncycastle.asn1.ASN1Sequence.getInstance(
                  ((org.bouncycastle.asn1.ASN1TaggedObject) field).getExplicitBaseObject());
          ASN1EncodableVector extensions = new ASN1EncodableVector();
          for (int j = 0; j < list.size(); j++) extensions.add(list.getObjectAt(j));
          extensions.add(list.getObjectAt(list.size() - 1));
          field = new DERTaggedObject(true, 3, new DERSequence(extensions));
        }
        fields.add(field);
      }
      byte[] newTbs = new DERSequence(fields).getEncoded("DER");
      byte[] sig = sign(signer.getPrivate(), newTbs);
      ASN1EncodableVector certificate = new ASN1EncodableVector();
      certificate.add(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(newTbs));
      certificate.add(cert.getSignatureAlgorithm());
      certificate.add(new org.bouncycastle.asn1.DERBitString(sig));
      return new DERSequence(certificate).getEncoded("DER");
    }

    byte[] topUp(byte[] samSki, long timestamp, long add) {
      return topUpWith(keyPair, samSki, timestamp, add);
    }

    static byte[] topUpWith(KeyPair signer, byte[] samSki, long timestamp, long add) {
      byte[] ts = u64(timestamp);
      byte[] amount = u32(add);
      byte[] sig = sign(signer.getPrivate(), concat("OPSAMTOPUP1".getBytes(), samSki, ts, amount));
      return concat(tlv(0x80, ts), tlv(0x81, amount), tlv(0x9E, sig));
    }
  }

  //
  // Encoding helpers.
  //

  static byte[] u64(long value) {
    byte[] out = new byte[8];
    for (int i = 0; i < 8; i++) out[i] = (byte) (value >>> (56 - 8 * i));
    return out;
  }

  static byte[] u32(long value) {
    byte[] out = new byte[4];
    for (int i = 0; i < 4; i++) out[i] = (byte) (value >>> (24 - 8 * i));
    return out;
  }

  static byte[] hex(String value) {
    String normalized = value.replace(" ", "");
    byte[] bytes = new byte[normalized.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(normalized.substring(2 * i, 2 * i + 2), 16);
    }
    return bytes;
  }

  static byte[] tlv(int tag, byte[] value) {
    byte[] length;
    if (value.length < 0x80) length = new byte[] {(byte) value.length};
    else if (value.length < 0x100) length = new byte[] {(byte) 0x81, (byte) value.length};
    else length = new byte[] {(byte) 0x82, (byte) (value.length >> 8), (byte) value.length};
    return concat(new byte[] {(byte) tag}, length, value);
  }

  static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) out.write(part, 0, part.length);
    return out.toByteArray();
  }

  static int derLength(byte[] data, int offset) {
    int first = data[offset] & 0xFF;
    if (first < 0x80) return first;
    int length = 0;
    for (int i = 0; i < (first & 0x7F); i++) length = (length << 8) | (data[offset + 1 + i] & 0xFF);
    return length;
  }

  static int derLengthSize(byte[] data, int offset) {
    int first = data[offset] & 0xFF;
    return first < 0x80 ? 1 : 1 + (first & 0x7F);
  }

  /** Finds a primitive one-octet tag in a flat TLV list. */
  static byte[] tlvValue(byte[] data, int tag) {
    int offset = 0;
    while (offset < data.length) {
      int current = data[offset] & 0xFF;
      int length = derLength(data, offset + 1);
      int value = offset + 1 + derLengthSize(data, offset + 1);
      if (current == tag) return Arrays.copyOfRange(data, value, value + length);
      offset = value + length;
    }
    throw new IllegalArgumentException("tag not found: " + Integer.toHexString(tag));
  }
}
