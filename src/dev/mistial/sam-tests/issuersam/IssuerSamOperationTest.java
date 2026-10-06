package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Date;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

/** Metering, top-up, access control, PoP/nonce negatives, GET DATA and TERMINATE. */
class IssuerSamOperationTest extends IssuerSamTestSupport {

  private byte[] samSki() {
    return tlvValue(status(), 0x8B);
  }

  private long quota() {
    return new BigInteger(1, tlvValue(status(), 0x86)).longValue();
  }

  @Test
  void quotaIsEnforcedAndTopUpResumesIssuance() throws Exception {
    Params params = Params.variant(root, 2);
    params.quota = 2;
    personalize(params);
    issueOne();
    issueOne();
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          assertSw(0x6A84, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN at quota");
        });
    byte[] head = chainHead();

    byte[] response =
        collect(
            transmit(0x80, 0x32, 0x00, 0x00, root.topUp(samSki(), INITIAL_TS + 1, 3)), "TOP UP");
    byte[][] parts = entryAndSignature(response);
    byte[] entry = parts[0];
    assertEquals(81, entry.length);
    assertEquals(0x03, entry[8]);
    assertArrayEquals(head, Arrays.copyOfRange(entry, 33, 65));
    assertArrayEquals(u64(INITIAL_TS + 1), Arrays.copyOfRange(entry, 65, 73));
    assertArrayEquals(u32(3), Arrays.copyOfRange(entry, 73, 77));
    assertArrayEquals(u32(5), Arrays.copyOfRange(entry, 77, 81));
    X509CertificateHolder samCert = samCertificate();
    assertTrue(
        verify(
            publicKey(samCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()),
            entry,
            parts[1]));
    assertEquals(5, quota());
    assertArrayEquals(sha256(entry), chainHead());
    assertEquals(
        referenceOpid(params, 3),
        IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issueOne().certificate)));
  }

  @Test
  void topUpNegativesLeaveStateUnchanged() {
    Params params = Params.variant(root, 0);
    params.quota = 10;
    personalize(params);
    byte[] ski = samSki();
    assertSw(0x9000, transmit(0x80, 0x32, 0, 0, root.topUp(ski, INITIAL_TS + 10, 1)), "first");
    byte[] head = chainHead();

    rejectTopUp(root.topUp(ski, INITIAL_TS + 10, 1), 0x6985, "replay");
    rejectTopUp(root.topUp(ski, INITIAL_TS + 9, 1), 0x6985, "older timestamp");
    rejectTopUp(root.topUp(ski, INITIAL_TS + 10, 2), 0x6985, "equal timestamp");
    rejectTopUp(TestRoot.topUpWith(newP256(), ski, INITIAL_TS + 11, 1), 0x6300, "bad signer");
    byte[] otherSki = ski.clone();
    otherSki[0] ^= 1;
    rejectTopUp(root.topUp(otherSki, INITIAL_TS + 11, 1), 0x6300, "wrong SAM SKI");
    rejectTopUp(root.topUp(ski, INITIAL_TS + 11, 0), 0x6A80, "add = 0");
    rejectTopUp(root.topUp(ski, INITIAL_TS + 11, 100_000_000L), 0x6A80, "quota > m");
    rejectTopUp(root.topUp(ski, INITIAL_TS + 11, 0xFFFFFFFFL), 0x6A80, "overflow");
    byte[] truncated = root.topUp(ski, INITIAL_TS + 11, 1);
    rejectTopUp(Arrays.copyOf(truncated, truncated.length - 1), 0x6A80, "truncated");
    // The unsigned u64 compare treats a timestamp with its top bit set as later.
    assertSw(
        0x9000,
        transmit(0x80, 0x32, 0, 0, root.topUp(ski, 0x8000_0000_0000_0000L, 1)),
        "high-bit timestamp is later");
    assertEquals(12, quota());
    assertTrue(!Arrays.equals(head, chainHead()));
  }

  private void rejectTopUp(byte[] data, int sw, String reason) {
    byte[] head = chainHead();
    long quota = quota();
    assertSw(sw, transmit(0x80, 0x32, 0x00, 0x00, data), reason);
    assertArrayEquals(head, chainHead(), reason + ": chain unchanged");
    assertEquals(quota, quota(), reason + ": quota unchanged");
  }

  @Test
  void issuanceRequiresSecureChannelAndPin() {
    Params params = Params.variant(root, 0);
    personalize(params);
    assertSw(0x6982, transmit(0x80, 0x84, 0x00, 0x00), "BEGIN plaintext");
    assertSw(0x6982, transmit(0x80, 0x2A, 0x00, 0xF9, new byte[4]), "ISSUE plaintext");
    assertSw(0x6982, transmit(0x80, 0xE6, 0x00, 0x00), "TERMINATE plaintext");
    assertSw(0x6982, transmit(0x80, 0xCA, 0x00, 0x04), "PARAMS plaintext");
    assertSw(0x6982, transmit(0x80, 0x20, 0x00, 0x81, PIN), "VERIFY plaintext");
    withMockedScp(
        () -> {
          assertSw(0x6982, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN without PIN");
          assertSw(0x63C4, transmit(0x84, 0x20, 0x00, 0x81, "00000000".getBytes()), "wrong 1");
          assertSw(0x63C4, transmit(0x84, 0x20, 0x00, 0x81), "status query");
          assertSw(0x63C3, transmit(0x84, 0x20, 0x00, 0x81, "00000000".getBytes()), "wrong 2");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "correct resets");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81), "validated");
          assertSw(0x9000, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN with PIN");
          // Deselect clears the PIN validation.
          assertSw(0x9000, selectSam(), "reselect");
          assertSw(0x6982, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN after reselect");
          for (int i = 5; i > 1; i--) {
            assertSw(
                0x63C0 | (i - 1),
                transmit(0x84, 0x20, 0x00, 0x81, "00000000".getBytes()),
                "wrong attempt");
          }
          assertSw(0x63C0, transmit(0x84, 0x20, 0x00, 0x81, "00000000".getBytes()), "last");
          assertSw(0x6983, transmit(0x84, 0x20, 0x00, 0x81, PIN), "blocked");
          assertSw(0x6982, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN when blocked");
        });
  }

  @Test
  void popAndNonceNegativesBurnNothing() {
    Params params = Params.variant(root, 0);
    personalize(params);
    byte[] head = chainHead();
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          KeyPair f9 = newP256();
          byte[] point = point(f9.getPublic());
          byte[] validity = defaultValidity();

          // No nonce.
          byte[] nonce = new byte[32];
          byte[] pop = sign(f9.getPrivate(), concat("OPF9POP".getBytes(), nonce, point));
          assertSw(0x6985, transmit(0x84, 0x2A, 0, 0xF9, issueData(point, pop, validity)), "no N");

          // Wrong nonce in the proof.
          beginIssuance();
          assertSw(0x6300, issueResponse(f9, new byte[32], validity), "PoP over wrong N");
          // The nonce was consumed by the failed attempt.
          byte[] used = beginIssuance();
          byte[] foreignPop =
              sign(newP256().getPrivate(), concat("OPF9POP".getBytes(), used, point));
          assertSw(
              0x6300,
              transmit(0x84, 0x2A, 0, 0xF9, issueData(point, foreignPop, validity)),
              "PoP by another key");
          assertSw(0x6985, issueResponse(f9, used, validity), "nonce reuse");

          // Any other command consumes the nonce.
          byte[] n2 = beginIssuance();
          assertSw(0x9000, transmit(0x80, 0xCA, 0x00, 0x01), "STATUS between");
          assertSw(0x6985, issueResponse(f9, n2, validity), "nonce consumed by STATUS");

          // Malformed requests.
          byte[] n3 = beginIssuance();
          byte[] goodPop = sign(f9.getPrivate(), concat("OPF9POP".getBytes(), n3, point));
          assertSw(
              0x6A80,
              transmit(0x84, 0x2A, 0, 0xF9, concat(issueData(point, goodPop, validity), hex("00"))),
              "trailing");
          beginIssuance();
          assertSw(
              0x6A80,
              transmit(
                  0x84,
                  0x2A,
                  0,
                  0xF9,
                  concat(
                      tlv(0x9E, goodPop),
                      tlv(0x86, point),
                      tlv(0x93, validity),
                      tlv(0x94, CAP_SHA256),
                      tlv(0x95, CPLC_SHA256))),
              "order");
          // The host measurements are required: the v1 form, a missing CPLC hash, swapped or
          // short measurements, and a repeated element are malformed.
          byte[] request = issueDataWithoutMeasurements(point, goodPop, validity);
          byte[][] malformed = {
            request,
            concat(request, tlv(0x94, CAP_SHA256)),
            concat(request, tlv(0x95, CPLC_SHA256), tlv(0x94, CAP_SHA256)),
            concat(request, tlv(0x94, Arrays.copyOf(CAP_SHA256, 31)), tlv(0x95, CPLC_SHA256)),
            concat(request, tlv(0x94, CAP_SHA256), tlv(0x95, Arrays.copyOf(CPLC_SHA256, 33))),
            concat(request, tlv(0x94, CAP_SHA256), tlv(0x94, CAP_SHA256)),
          };
          for (int i = 0; i < malformed.length; i++) {
            beginIssuance();
            assertSw(
                0x6A80,
                transmitChained(0x84, 0x2A, 0, 0xF9, malformed[i]),
                "measurement form " + i);
          }
          // A chain longer than the largest well-formed request is refused while it is assembled.
          beginIssuance();
          assertSw(
              0x6700,
              transmitChained(
                  0x84, 0x2A, 0, 0xF9, concat(issueData(point, goodPop, validity), new byte[40])),
              "oversize chain");
          byte[] offCurve = point.clone();
          offCurve[64] ^= 1;
          beginIssuance();
          assertSw(
              0x6A80,
              transmit(0x84, 0x2A, 0, 0xF9, issueData(offCurve, goodPop, validity)),
              "curve");
          beginIssuance();
          assertSw(
              0x6A80,
              transmit(0x84, 0x2A, 0, 0xF9, issueData(root.point, goodPop, validity)),
              "root point");
          byte[] n4 = beginIssuance();
          assertSw(
              0x6A80,
              issueResponse(
                  f9,
                  n4,
                  validity(
                      new Date(), new Date(System.currentTimeMillis() + 40L * 365 * 86_400_000L))),
              "notAfter beyond SAM");
          byte[] n5 = beginIssuance();
          long now = System.currentTimeMillis();
          assertSw(
              0x6A80, issueResponse(f9, n5, validity(new Date(now), new Date(now))), "nb == na");
          beginIssuance();
          assertSw(0x6A86, transmit(0x84, 0x2A, 0, 0x9A, new byte[4]), "P2");
        });
    assertArrayEquals(head, chainHead(), "chain unchanged");
    assertEquals(0, issued(), "nothing burned");
    Issued issued = issueOne();
    assertEquals(
        referenceOpid(params, 1),
        IssuerSamIssuanceTest.serialNumberOf(uncheckedHolder(issued.certificate)));
  }

  @Test
  void nonceDeliveredThroughGetResponseStaysValidForIssue() {
    Params params = Params.variant(root, 0);
    personalize(params);
    Issued issued =
        withMockedScp(
            () -> {
              assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
              // Le = 16 forces the 32-octet nonce through 61xx and GET RESPONSE.
              ResponseAPDU first = transmit(new CommandAPDU(0x84, 0x84, 0x00, 0x00, 16));
              assertSw(0x6110, first, "BEGIN with short Le");
              ResponseAPDU rest = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, 16));
              assertSw(0x9000, rest, "GET RESPONSE");
              byte[] nonce = concat(first.getData(), rest.getData());
              assertEquals(32, nonce.length);
              KeyPair f9 = newP256();
              Issued result =
                  parseIssued(collect(issueResponse(f9, nonce, defaultValidity()), "ISSUE"));
              result.f9 = f9;
              return result;
            });
    assertEquals(
        referenceOpid(params, 1),
        IssuerSamIssuanceTest.serialNumberOf(uncheckedHolder(issued.certificate)));
  }

  @Test
  void paramsDigestStaysTheProvisionedValueAfterTopUp() {
    Params params = Params.variant(root, 0);
    personalize(params);
    assertSw(0x9000, transmit(0x80, 0x32, 0, 0, root.topUp(samSki(), INITIAL_TS + 1, 2)), "TOP UP");
    issueOne();
    byte[] prm = withMockedScp(() -> collect(transmit(0x84, 0xCA, 0x00, 0x04), "GET PARAMS"));
    assertArrayEquals(u32(1), tlvValue(prm, 0x85));
    assertArrayEquals(u32(params.quota + 2), tlvValue(prm, 0x86));
    assertArrayEquals(referenceParamsDigest(params), tlvValue(prm, 0x93));
  }

  @Test
  void lostResponseIsRecoverableFromRamUntilNextBegin() {
    Params params = Params.variant(root, 4);
    personalize(params);
    Issued issued = issueOne();
    withMockedScp(
        () -> {
          byte[] again = collect(transmit(0x84, 0xCA, 0x00, 0x05), "LAST RESULT");
          assertArrayEquals(issued.raw, again);
          assertSw(0x6982, transmit(0x80, 0xCA, 0x00, 0x05), "LAST RESULT needs SCP");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          beginIssuance();
          assertSw(0x6985, transmit(0x84, 0xCA, 0x00, 0x05), "cleared by BEGIN");
        });
    byte[][] last = entryAndSignature(collect(transmit(0x80, 0xCA, 0x00, 0x03), "LAST ENTRY"));
    assertArrayEquals(issued.entry, last[0]);
  }

  @Test
  void extendedLengthReturnsTheWholeIssueResponse() {
    Params params = Params.variant(root, 0);
    personalize(params);
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          KeyPair f9 = newP256();
          byte[] nonce = beginIssuance();
          byte[] point = point(f9.getPublic());
          byte[] pop = sign(f9.getPrivate(), concat("OPF9POP".getBytes(), nonce, point));
          ResponseAPDU response =
              transmit(
                  new CommandAPDU(
                      0x84, 0x2A, 0x00, 0xF9, issueData(point, pop, defaultValidity()), 65536));
          // Ne beyond what the transport delivers in one response continues with 61xx.
          parseIssued(collect(response, "extended ISSUE"));
        });
  }

  @Test
  void terminateSignsFinalEntryAndClearsTheKey() throws Exception {
    Params params = Params.variant(root, 9);
    personalize(params);
    issueOne();
    byte[] head = chainHead();
    byte[] samPoint = samCertificate().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
    byte[] response =
        withMockedScp(
            () -> {
              assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
              return collect(transmit(0x84, 0xE6, 0x00, 0x00), "TERMINATE");
            });
    byte[][] parts = entryAndSignature(response);
    assertEquals(73, parts[0].length);
    assertEquals(0x04, parts[0][8]);
    assertArrayEquals(head, Arrays.copyOfRange(parts[0], 33, 65));
    assertArrayEquals(u32(1), Arrays.copyOfRange(parts[0], 65, 69));
    assertTrue(verify(publicKey(samPoint), parts[0], parts[1]));
    assertEquals(LC_TERMINATED, lifecycle());
    withMockedScp(
        () -> {
          assertSw(0x6985, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN after TERMINATE");
          assertSw(0x6985, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY after TERMINATE");
          assertSw(0x6985, transmit(0x84, 0x46, 0x00, 0x00), "GENERATE after TERMINATE");
        });
    assertSw(0x6985, transmit(0x80, 0xCA, 0x01, 0x01, new byte[16]), "no signed STATUS");
    assertSw(0x6985, transmit(0x80, 0x32, 0, 0, root.topUp(samSki(), INITIAL_TS + 1, 1)), "TOP UP");
    byte[] last = collect(transmit(0x80, 0xCA, 0x00, 0x03), "LAST ENTRY");
    assertArrayEquals(concat(new byte[] {0x71, (byte) parts[0].length}, parts[0]), last);
  }

  @Test
  void classAndParameterErrors() {
    assertSw(0x9000, selectSam(), "SELECT");
    assertSw(0x6E00, transmit(0x00, 0xCA, 0x00, 0x01), "CLA 00");
    assertSw(0x6E00, transmit(0xA0, 0xCA, 0x00, 0x01), "CLA A0");
    assertSw(0x6D00, transmit(0x80, 0x10, 0x00, 0x00), "unknown INS");
    assertSw(0x6A86, transmit(0x80, 0xCA, 0x00, 0x09), "unknown GET DATA");
    assertSw(0x6A86, transmit(0x80, 0xCA, 0x02, 0x01, new byte[16]), "unknown P1");
    assertSw(0x6A80, transmit(0x80, 0xCA, 0x01, 0x01, new byte[15]), "short status nonce");
    assertSw(0x6985, transmit(0x80, 0xCA, 0x01, 0x01, new byte[16]), "signed before key");
    assertSw(0x6985, transmit(0x00, 0xC0, 0x00, 0x00), "GET RESPONSE without pending");
    assertSw(0x6985, transmit(0x80, 0xCA, 0x00, 0x02), "no cert");
    assertSw(0x6985, transmit(0x80, 0xCA, 0x00, 0x03), "no entry");
    assertSw(0x6985, transmit(0x80, 0x32, 0x00, 0x00, new byte[4]), "TOP UP before LOCK");
  }

  private static X509CertificateHolder uncheckedHolder(byte[] encoded) {
    try {
      return new X509CertificateHolder(encoded);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
