package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Date;
import java.util.function.Consumer;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

/** Personalization: lifecycle, PUT PARAMETERS validation, certificate policy and LOCK. */
class IssuerSamPersonalizationTest extends IssuerSamTestSupport {

  @Test
  void selectReturnsFciWithVersionAndLifecycle() {
    ResponseAPDU response = selectSam();
    assertSw(0x9000, response, "SELECT");
    assertArrayEquals(hex("6F07 80020001 8101 5A"), response.getData());
  }

  @Test
  void happyPathWalksEveryLifecycleState() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertEquals(LC_INSTALLED, lifecycle());
          assertSw(0x9000, putParameters(params), "PUT PARAMETERS");
          assertEquals(LC_PARAMS_SET, lifecycle());
          // PUT PARAMETERS may repeat before the key exists.
          params.quota = 5;
          assertSw(0x9000, putParameters(params), "PUT PARAMETERS again");
          assertEquals(5, new BigInteger(1, tlvValue(status(), 0x86)).longValue());
          assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "SET PIN");
          byte[] point = generateKey();
          assertEquals(LC_KEY_GENERATED, lifecycle());
          assertArrayEquals(ski(point), tlvValue(status(), 0x8B));
          byte[] cert = root.issueSamCertificate(point, params, new SamCertSpec());
          ResponseAPDU loaded = transmitChained(0x84, 0xD4, 0x00, 0x00, cert);
          assertSw(0x9000, loaded, "LOAD SAM CERTIFICATE");
          assertArrayEquals(concat(hex("8B14"), ski(point)), loaded.getData());
          assertEquals(LC_CERT_LOADED, lifecycle());
          // The certificate may be reloaded until LOCK.
          assertSw(0x9000, transmitChained(0x84, 0xD4, 0x00, 0x00, cert), "reload");
          assertArrayEquals(
              cert, collect(transmit(0x80, 0xCA, 0x00, 0x02), "GET SAM CERT"), "stored cert");

          byte[][] genesis = entryAndSignature(collect(transmit(0x84, 0xD6, 0x00, 0x00), "LOCK"));
          assertEquals(LC_OPERATIONAL, lifecycle());
          byte[] entry = genesis[0];
          assertEquals(141, entry.length);
          assertArrayEquals("OPSAMLE1".getBytes(), Arrays.copyOf(entry, 8));
          assertEquals(0x01, entry[8]);
          assertArrayEquals(ski(point), Arrays.copyOfRange(entry, 9, 29));
          assertArrayEquals(hex("00000001"), Arrays.copyOfRange(entry, 29, 33));
          assertArrayEquals(new byte[32], Arrays.copyOfRange(entry, 33, 65));
          assertArrayEquals(sha256(cert), Arrays.copyOfRange(entry, 65, 97));
          assertArrayEquals(referenceParamsDigest(params), Arrays.copyOfRange(entry, 97, 129));
          assertArrayEquals(u32(5), Arrays.copyOfRange(entry, 129, 133));
          assertArrayEquals(u64(INITIAL_TS), Arrays.copyOfRange(entry, 133, 141));
          assertEquals(true, verify(publicKey(point), entry, genesis[1]));
          assertArrayEquals(sha256(entry), chainHead());

          // GET DATA PARAMS echoes the provisioned values (ASCII, most significant first).
          byte[] prm = collect(transmit(0x84, 0xCA, 0x00, 0x04), "GET PARAMS");
          assertArrayEquals("1234".getBytes(), tlvValue(prm, 0x82));
          assertArrayEquals("9123".getBytes(), tlvValue(prm, 0x83));
          assertArrayEquals(
              concat(
                  hex("8204"),
                  "1234".getBytes(),
                  hex("8304"),
                  "9123".getBytes(),
                  hex("8504"),
                  u32(0),
                  hex("8604"),
                  u32(5),
                  hex("9320"),
                  referenceParamsDigest(params)),
              prm,
              "PARAMS carries only non-secret fields");
          // The LCG state never leaves the SAM: STATUS has no current-x tag, and no format or k.
          byte[] statusTlv = status();
          assertThrows(IllegalArgumentException.class, () -> tlvValue(statusTlv, 0x8D));
          assertThrows(IllegalArgumentException.class, () -> tlvValue(statusTlv, 0x81));
          assertThrows(IllegalArgumentException.class, () -> tlvValue(statusTlv, 0x84));
          assertArrayEquals("9123".getBytes(), tlvValue(statusTlv, 0x83));
          assertArrayEquals(u32(100_000_000L), tlvValue(statusTlv, 0x87));
        });
  }

  @Test
  void personalizationWithoutSecureChannelIsRefused() {
    Params params = Params.variant(root, 0);
    assertSw(0x9000, selectSam(), "SELECT");
    assertSw(0x6982, transmitChained(0x80, 0xD0, 0x00, 0x00, params.encode()), "PUT plaintext");
    assertSw(0x6982, transmit(0x80, 0xD2, 0x00, 0x81, PIN), "SET PIN plaintext");
    assertSw(0x6982, transmit(0x80, 0x46, 0x00, 0x00), "GENERATE plaintext");
    assertSw(0x6982, transmit(0x80, 0xD6, 0x00, 0x00), "LOCK plaintext");
    // An SM class without an authenticated session is refused before any parsing.
    assertSw(0x6982, transmit(0x84, 0x46, 0x00, 0x00, new byte[8]), "SM class without SCP");
    withMockedScp(() -> assertEquals(LC_INSTALLED, lifecycle()));
  }

  @Test
  void commandsOutOfOrderReturn6985() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x6985, transmit(0x84, 0x46, 0x00, 0x00), "GENERATE before PARAMS");
          assertSw(0x6985, transmit(0x84, 0xD4, 0x00, 0x00, new byte[] {0x30, 0x00}), "LOAD early");
          assertSw(0x6985, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK early");
          assertSw(0x6985, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY before LOCK");
          assertSw(0x9000, putParameters(params), "PUT PARAMETERS");
          generateKey();
          assertSw(0x6985, putParameters(params), "PUT after GENERATE");
          assertSw(0x6985, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK without cert");
          assertEquals(LC_KEY_GENERATED, lifecycle());
        });
  }

  @Test
  void lockRequiresOperatorPin() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x9000, putParameters(params), "PUT");
          byte[] point = generateKey();
          assertSw(
              0x9000,
              transmitChained(
                  0x84, 0xD4, 0, 0, root.issueSamCertificate(point, params, new SamCertSpec())),
              "LOAD");
          assertSw(0x6985, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK without PIN");
          assertSw(0x6A80, transmit(0x84, 0xD2, 0x00, 0x81, "12345".getBytes()), "short PIN");
          assertSw(0x6A80, transmit(0x84, 0xD2, 0x00, 0x81, new byte[17]), "long PIN");
          assertEquals(LC_CERT_LOADED, lifecycle());
        });
  }

  @Test
  void lockRequiresCommitCapacity() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x9000, putParameters(params), "PUT");
          assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "PIN");
          byte[] point = generateKey();
          assertSw(
              0x9000,
              transmitChained(
                  0x84, 0xD4, 0, 0, root.issueSamCertificate(point, params, new SamCertSpec())),
              "LOAD");
          try (org.mockito.MockedStatic<javacard.framework.JCSystem> system =
              org.mockito.Mockito.mockStatic(
                  javacard.framework.JCSystem.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            system.when(javacard.framework.JCSystem::getMaxCommitCapacity).thenReturn((short) 511);
            assertSw(0x6A84, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK with 511 octets");
          }
          assertEquals(LC_CERT_LOADED, lifecycle());
          assertSw(0x9000, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK");
        });
  }

  @Test
  void secureChannelCommandsRouteToTheSecurityDomainAndResetTheOperatorSession() {
    personalize(Params.variant(root, 0));
    try (org.mockito.MockedStatic<org.globalplatform.GPSystem> gp =
        org.mockito.Mockito.mockStatic(org.globalplatform.GPSystem.class)) {
      org.globalplatform.SecureChannel channel =
          org.mockito.Mockito.mock(org.globalplatform.SecureChannel.class);
      gp.when(org.globalplatform.GPSystem::getSecureChannel).thenReturn(channel);
      org.mockito.Mockito.when(
              channel.unwrap(
                  org.mockito.Mockito.any(byte[].class),
                  org.mockito.Mockito.anyShort(),
                  org.mockito.Mockito.anyShort()))
          .thenAnswer(invocation -> (short) invocation.getArgument(2));
      org.mockito.Mockito.when(channel.processSecurity(org.mockito.Mockito.any()))
          .thenReturn((short) 0);
      org.mockito.Mockito.when(channel.getSecurityLevel())
          .thenReturn(
              (byte)
                  (org.globalplatform.SecureChannel.AUTHENTICATED
                      | org.globalplatform.SecureChannel.C_DECRYPTION
                      | org.globalplatform.SecureChannel.C_MAC));
      assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
      assertSw(0x9000, transmit(0x80, 0x50, 0x00, 0x00, new byte[8]), "INITIALIZE UPDATE");
      org.mockito.Mockito.verify(channel).processSecurity(org.mockito.Mockito.any());
      assertSw(0x6982, transmit(0x84, 0x84, 0x00, 0x00), "new session needs the PIN again");
      assertSw(0x6E00, transmit(0x84, 0x50, 0x00, 0x00, new byte[8]), "INITIALIZE UPDATE CLA");
      assertSw(0x6E00, transmit(0x80, 0x82, 0x00, 0x00, new byte[8]), "EXTERNAL AUTH CLA");
    }
  }

  @Test
  void eachParameterRuleIsEnforced() {
    rejectParams("issuerId > 9999", p -> p.issuerId = 10000);
    rejectParams("batch > 9999", p -> p.batch = 10000);
    rejectParams("modulus 10^7", p -> p.modulus = 10_000_000);
    rejectParams("modulus 10^5", p -> p.modulus = 100_000);
    rejectParams("modulus off by one", p -> p.modulus = 100_000_001);
    rejectParams("x0 >= m", p -> p.x0 = 100_000_000);
    rejectParams("a >= m", p -> p.a = 100_000_001);
    rejectParams("c >= m", p -> p.c = 100_000_003);
    rejectParams("c even", p -> p.c = 8);
    rejectParams("c multiple of 5", p -> p.c = 25);
    rejectParams("a = 1", p -> p.a = 1);
    rejectParams("a = 11 (1 mod 10, not 1 mod 20)", p -> p.a = 11);
    rejectParams("a = 23", p -> p.a = 23);
    rejectParams("quota > m", p -> p.quota = 100_000_001);
    rejectParams(
        "root key off curve",
        p -> {
          p.rootPoint = p.rootPoint.clone();
          p.rootPoint[64] ^= 1;
        });
    rejectParams(
        "template with serialNumber", p -> p.template = new X500Name("CN=x,SERIALNUMBER=1"));
    rejectParams(
        "template > 96 octets",
        p -> p.template = new X500Name("CN=" + repeat('t', 90) + ",O=OpenPhysical"));
    rejectParams(
        "SAM subject > 128 octets", p -> p.samSubject = new X500Name("CN=" + repeat('s', 130)));
  }

  @Test
  void everyRejectedLcgVectorIsRefused() throws Exception {
    String directory = System.getProperty("openfips201.testVectors", "test-vectors");
    com.google.gson.JsonObject vectors =
        com.google.gson.JsonParser.parseString(
                new String(
                    java.nio.file.Files.readAllBytes(
                        java.nio.file.Paths.get(directory, "opid", "lcg.json")),
                    java.nio.charset.StandardCharsets.UTF_8))
            .getAsJsonObject();
    int checked = 0;
    for (com.google.gson.JsonElement element : vectors.getAsJsonArray("rejected")) {
      com.google.gson.JsonObject vector = element.getAsJsonObject();
      rejectParams(
          vector.get("reason").getAsString(),
          p -> {
            p.a = vector.get("a").getAsLong();
            p.c = vector.get("c").getAsLong();
            p.x0 = vector.get("x0").getAsLong();
          });
      checked++;
    }
    assertEquals(9, checked);
  }

  @Test
  void parameterEncodingMustBeStrictDer() {
    Params params = Params.variant(root, 0);
    byte[] good = params.encode();
    // Non-minimal INTEGER: version encoded as 02 02 00 05.
    byte[] versionBad = replaceFirst(good, hex("020105"), hex("02020005"));
    rejectRaw("non-minimal INTEGER", fixOuterLength(versionBad));
    // BER indefinite outer length.
    byte[] indefinite =
        concat(
            hex("3080"),
            Arrays.copyOfRange(good, derLengthSize(good, 1) + 1, good.length),
            hex("0000"));
    rejectRaw("indefinite length", indefinite);
    // Non-minimal long-form length on the outer SEQUENCE.
    byte[] longForm =
        concat(
            hex("3082"),
            new byte[] {(byte) ((good.length - 3) >> 8), (byte) (good.length - 3)},
            Arrays.copyOfRange(good, 3, good.length));
    if (good[1] == (byte) 0x81) rejectRaw("non-minimal length", longForm);
    // Trailing octets and wrong version.
    rejectRaw("trailing octet", concat(good, hex("00")));
    rejectRaw("version 1", fixOuterLength(replaceFirst(good, hex("020105"), hex("020101"))));
    // Earlier versions are refused even when the remaining fields are well formed.
    for (int version = 2; version <= 4; version++) {
      Params older = Params.variant(root, 0);
      older.version = version;
      rejectRaw("version " + version, older.encode());
    }
    // A v3-style issue sequence with a leading format field is refused.
    byte[] issue = hex("B00E 020100 020204D2 020223A3 02010A");
    byte[] withFormat = replaceFirst(good, hex("B00B 020204D2 020223A3 02010A"), issue);
    rejectRaw("format field", fixOuterLength(withFormat));
    // The FF1 key is required and exactly 32 octets.
    Params noKey = Params.variant(root, 0);
    noKey.includeFpeKey = false;
    rejectRaw("missing wrappedFpeKey", noKey.encode());
    Params shortWrap = Params.variant(root, 0);
    shortWrap.wrappedOverride = new byte[32];
    rejectRaw("32-octet wrappedKey", shortWrap.encode());
    Params longWrap = Params.variant(root, 0);
    longWrap.wrappedOverride = new byte[48];
    rejectRaw("48-octet wrappedKey", longWrap.encode());
    Params shortEph = Params.variant(root, 0);
    shortEph.hostEphOverride = new byte[33];
    rejectRaw("compressed host point", shortEph.encode());
    // A plain v4 fpeKey [24] OCTET STRING is not a wrappedFpeKey SEQUENCE.
    byte[] plainKey = concat(hex("9820"), new byte[32]);
    byte[] wrappedField = Arrays.copyOfRange(good, good.length - 111, good.length);
    assertEquals(0xB8, wrappedField[0] & 0xFF, "wrappedFpeKey is the last field");
    rejectRaw("plain fpeKey", fixOuterLength(replaceFirst(good, wrappedField, plainKey)));
    // Wrong type OID.
    byte[] oid = hex("2B0601040183C443140A0A01");
    byte[] badOid = oid.clone();
    badOid[badOid.length - 1] = 0x02;
    rejectRaw("type OID", replaceFirst(good, oid, badOid));
  }

  @Test
  void samSubjectIsOptional() {
    Params params = Params.variant(root, 3);
    params.includeSamSubject = false;
    byte[] genesis = personalize(params);
    assertEquals(141, entryAndSignature(genesis)[0].length);
    withMockedScp(() -> assertEquals(LC_OPERATIONAL, lifecycle()));
  }

  @Test
  void certificatePolicyViolationsAreRejectedWith6A80() {
    rejectCert("pathLen 0", s -> s.pathLen = 0, 0x6A80);
    rejectCert("pathLen 2", s -> s.pathLen = 2, 0x6A80);
    rejectCert("BC missing", s -> s.pathLen = null, 0x6A80);
    rejectCert("BC not critical", s -> s.basicConstraintsCritical = false, 0x6A80);
    rejectCert("KU missing", s -> s.includeKeyUsage = false, 0x6A80);
    rejectCert("KU without keyCertSign", s -> s.keyUsage = KeyUsage.digitalSignature, 0x6A80);
    rejectCert("SKI missing", s -> s.includeSki = false, 0x6A80);
    rejectCert("SKI wrong", s -> s.skiOverride = new byte[20], 0x6A80);
    rejectCert("batch extension missing", s -> s.includeBatch = false, 0x6A80);
    rejectCert("unknown critical extension", s -> s.unknownCritical = true, 0x6A80);
    rejectCert("duplicate extension", s -> s.duplicateSki = true, 0x6A80);
    rejectCert(
        "subject differs from expected",
        s -> s.subjectOverride = new X500Name("CN=Other SAM,O=OpenPhysical Test"),
        0x6A80);
    rejectCert("foreign SPKI", s -> s.pointOverride = point(newP256().getPublic()), 0x6A80);
    KeyPair stranger = newP256();
    rejectCert("non-root signer", s -> s.signerOverride = stranger, 0x6300);
  }

  @Test
  void batchExtensionMustMatchStoredParameters() throws Exception {
    Params params = Params.variant(root, 0);
    Params other = Params.variant(root, 0);
    other.quota = params.quota + 1;
    byte[] mismatchedQuota = root.batchExtension(other);
    other = Params.variant(root, 0);
    other.x0 = params.x0 + 1;
    byte[] mismatchedDigest = root.batchExtension(other);
    other = Params.variant(root, 0);
    other.batch = params.batch - 1;
    byte[] mismatchedBatch = root.batchExtension(other);
    rejectCert("quota mismatch", s -> s.batchOverride = mismatchedQuota, 0x6A80);
    rejectCert("paramsDigest mismatch", s -> s.batchOverride = mismatchedDigest, 0x6A80);
    rejectCert("batch mismatch", s -> s.batchOverride = mismatchedBatch, 0x6A80);
    // Batch extension v2 (no allocationSeq or registryHead) is no longer accepted.
    org.bouncycastle.asn1.ASN1Sequence v3 =
        org.bouncycastle.asn1.ASN1Sequence.getInstance(root.batchExtension(params));
    org.bouncycastle.asn1.ASN1EncodableVector v2 = new org.bouncycastle.asn1.ASN1EncodableVector();
    v2.add(new org.bouncycastle.asn1.ASN1Integer(2));
    for (int i = 1; i < 6; i++) v2.add(v3.getObjectAt(i));
    byte[] versionTwo = new org.bouncycastle.asn1.DERSequence(v2).getEncoded("DER");
    rejectCert("batch extension v2", s -> s.batchOverride = versionTwo, 0x6A80);
    org.bouncycastle.asn1.ASN1EncodableVector truncated =
        new org.bouncycastle.asn1.ASN1EncodableVector();
    for (int i = 0; i < 7; i++) truncated.add(v3.getObjectAt(i));
    byte[] noRegistry = new org.bouncycastle.asn1.DERSequence(truncated).getEncoded("DER");
    rejectCert("missing registryHead", s -> s.batchOverride = noRegistry, 0x6A80);
  }

  @Test
  void personalizationAfterLockReturns6985() {
    Params params = Params.variant(root, 0);
    personalize(params);
    withMockedScp(
        () -> {
          assertSw(0x6985, putParameters(params), "PUT after LOCK");
          assertSw(0x6985, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "SET PIN after LOCK");
          assertSw(0x6985, transmit(0x84, 0x46, 0x00, 0x00), "GENERATE after LOCK");
          assertSw(0x6985, transmit(0x84, 0xD4, 0x00, 0x00, new byte[] {0x30, 0x00}), "LOAD");
          assertSw(0x6985, transmit(0x84, 0xD6, 0x00, 0x00), "LOCK again");
          assertEquals(LC_OPERATIONAL, lifecycle());
        });
  }

  @Test
  void regeneratingTheKeyDropsTheCertificate() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x9000, putParameters(params), "PUT");
          assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "PIN");
          byte[] first = generateKey();
          byte[] cert = root.issueSamCertificate(first, params, new SamCertSpec());
          assertSw(0x9000, transmitChained(0x84, 0xD4, 0, 0, cert), "LOAD");
          assertEquals(LC_CERT_LOADED, lifecycle());
          byte[] second = generateKey();
          assertFalse(Arrays.equals(first, second), "new key");
          assertEquals(LC_KEY_GENERATED, lifecycle());
          assertSw(0x6985, transmit(0x80, 0xCA, 0x00, 0x02), "no certificate after regenerate");
          assertSw(0x6A80, transmitChained(0x84, 0xD4, 0, 0, cert), "old cert no longer matches");
          assertSw(
              0x9000,
              transmitChained(
                  0x84, 0xD4, 0, 0, root.issueSamCertificate(second, params, new SamCertSpec())),
              "new cert");
        });
  }

  @Test
  void chainedFramesMustKeepTheirProtection() {
    Params params = Params.variant(root, 0);
    byte[] packet = params.encode();
    int split = packet.length - 200;
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(
              0x9000,
              transmit(new CommandAPDU(0x94, 0xD0, 0, 0, Arrays.copyOf(packet, split))),
              "first frame");
          // A plaintext continuation frame is a protection downgrade.
          assertSw(
              0x6982,
              transmit(
                  new CommandAPDU(
                      0x80, 0xD0, 0, 0, Arrays.copyOfRange(packet, split, packet.length))),
              "downgraded frame");
          assertEquals(LC_INSTALLED, lifecycle());
          // An unrelated command abandons the chain: the tail alone is not a packet.
          assertSw(0x9000, transmit(0x84, 0x4A, 0x00, 0x00), "GENERATE TRANSPORT KEY");
          assertSw(
              0x9000,
              transmit(new CommandAPDU(0x94, 0xD0, 0, 0, Arrays.copyOf(packet, split))),
              "first frame again");
          assertSw(0x9000, transmit(0x80, 0xCA, 0x00, 0x01), "interleaved STATUS");
          assertSw(
              0x6A80,
              transmit(0x84, 0xD0, 0, 0, Arrays.copyOfRange(packet, split, packet.length)),
              "orphaned tail");
          // The chaining bit is refused on every other instruction.
          assertSw(0x6E00, transmit(0x94, 0x46, 0x00, 0x00), "chained GENERATE");
        });
  }

  @Test
  void contactlessSelectIsDeclined() {
    try (org.mockito.MockedStatic<javacard.framework.APDU> mocked =
        org.mockito.Mockito.mockStatic(javacard.framework.APDU.class)) {
      mocked
          .when(javacard.framework.APDU::getProtocol)
          .thenReturn(
              (byte)
                  (javacard.framework.APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A
                      | javacard.framework.APDU.PROTOCOL_T1));
      assertFalse(selectSam().getSW() == 0x9000, "SAM is contact-only");
    }
  }

  //
  // Helpers.
  //

  /**
   * The packet is wrapped to the SAM's live transport key, so only the mutated rule can cause the
   * 6A80.
   */
  private void rejectParams(String reason, Consumer<Params> mutation) {
    Params params = Params.variant(root, 0);
    mutation.accept(params);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          byte before = lifecycle();
          assertSw(0x6A80, putParameters(params), reason);
          assertEquals(before, lifecycle(), reason + ": lifecycle unchanged");
        });
  }

  private void rejectRaw(String reason, byte[] packet) {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          byte before = lifecycle();
          assertSw(0x6A80, putRawParameters(packet), reason);
          assertEquals(before, lifecycle(), reason + ": lifecycle unchanged");
        });
  }

  private void rejectCert(String reason, Consumer<SamCertSpec> mutation, int sw) {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          if (lifecycle() == LC_INSTALLED) {
            assertSw(0x9000, putParameters(params), "PUT");
            assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "PIN");
          }
          byte[] point = generateKey();
          SamCertSpec spec = new SamCertSpec();
          mutation.accept(spec);
          byte[] cert = root.issueSamCertificate(point, params, spec);
          assertSw(sw, transmitChained(0x84, 0xD4, 0, 0, cert), reason);
          assertEquals(LC_KEY_GENERATED, lifecycle(), reason + ": lifecycle unchanged");
        });
  }

  private static String repeat(char c, int n) {
    char[] chars = new char[n];
    Arrays.fill(chars, c);
    return new String(chars);
  }

  private static byte[] replaceFirst(byte[] data, byte[] from, byte[] to) {
    for (int i = 0; i + from.length <= data.length; i++) {
      if (Arrays.equals(Arrays.copyOfRange(data, i, i + from.length), from)) {
        return concat(
            Arrays.copyOf(data, i), to, Arrays.copyOfRange(data, i + from.length, data.length));
      }
    }
    throw new IllegalArgumentException("pattern not found");
  }

  /** Re-encodes the outer SEQUENCE length after a content edit. */
  private static byte[] fixOuterLength(byte[] packet) {
    int header = 1 + derLengthSize(packet, 1);
    byte[] content = Arrays.copyOfRange(packet, header, packet.length);
    return tlv(0x30, content);
  }

  @SuppressWarnings("unused")
  private static Date days(int n) {
    return new Date(System.currentTimeMillis() + n * 86_400_000L);
  }
}
