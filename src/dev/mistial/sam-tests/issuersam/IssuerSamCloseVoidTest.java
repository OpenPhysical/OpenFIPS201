package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

/** VOID, CLOSE, CHANGE OPERATOR PIN, the CLOSED gating table and the batch extension v3 binding. */
class IssuerSamCloseVoidTest extends IssuerSamTestSupport {

  private byte[] samPoint() throws Exception {
    return samCertificate().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
  }

  private byte[] voidRequest(long seq, int reason) {
    return concat(tlv(0x80, u32(seq)), tlv(0x81, new byte[] {(byte) reason}));
  }

  private byte[][] voidOk(long seq, int reason) {
    return withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          return entryAndSignature(
              collect(transmit(0x84, 0x2E, 0x00, 0x00, voidRequest(seq, reason)), "VOID " + seq));
        });
  }

  private byte[][] close() {
    return withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          return entryAndSignature(collect(transmit(0x84, 0xE8, 0x00, 0x00), "CLOSE"));
        });
  }

  @Test
  void statusReportsTheBatchExtensionRegistryBinding() {
    Params params = Params.variant(root, 4);
    params.allocationSeq = 0xFFFF_FFFEL;
    params.registryHead = sha256("registry head 4".getBytes());
    personalize(params);
    byte[] status = status();
    assertArrayEquals(u32(0xFFFF_FFFEL), tlvValue(status, 0x8F));
    assertArrayEquals(params.registryHead, tlvValue(status, 0x90));
  }

  @Test
  void voidRecomputesTheIssuedOpidAndExtendsTheChain() throws Exception {
    Params params = Params.variant(root, 2);
    params.quota = 5;
    personalize(params);
    String[] issued = new String[4];
    for (int n = 1; n <= 3; n++) {
      issued[n] =
          IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issueOne().certificate));
    }
    byte[] point = samPoint();
    for (long seq : new long[] {2, 1, 3, 2}) {
      byte[] head = chainHead();
      byte[][] response = voidOk(seq, 0x07);
      byte[] entry = response[0];
      assertEquals(88, entry.length);
      assertEquals(0x05, entry[8]);
      assertArrayEquals(head, Arrays.copyOfRange(entry, 33, 65));
      assertArrayEquals(u32(seq), Arrays.copyOfRange(entry, 65, 69));
      assertEquals(17, entry[69]);
      assertEquals(
          issued[(int) seq], new String(entry, 70, 17, StandardCharsets.US_ASCII), "seq " + seq);
      assertEquals(0x07, entry[87]);
      assertTrue(verify(publicKey(point), entry, response[1]));
      assertArrayEquals(sha256(entry), chainHead());
    }
    assertEquals(3, issued(), "VOID does not change issued");
  }

  @Test
  void voidAcceptsOnlyIssuedNumbersWithSecureChannelAndPin() {
    Params params = Params.variant(root, 0);
    personalize(params);
    issueOne();
    byte[] head = chainHead();
    assertSw(0x6982, transmit(0x80, 0x2E, 0x00, 0x00, voidRequest(1, 0)), "plaintext");
    withMockedScp(
        () -> {
          // Reselecting clears the operator session left by the issuance.
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x6982, transmit(0x84, 0x2E, 0x00, 0x00, voidRequest(1, 0)), "no PIN");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          assertSw(0x6A80, transmit(0x84, 0x2E, 0x00, 0x00, voidRequest(0, 0)), "seq 0");
          assertSw(0x6A80, transmit(0x84, 0x2E, 0x00, 0x00, voidRequest(2, 0)), "seq > issued");
          assertSw(
              0x6A80,
              transmit(0x84, 0x2E, 0x00, 0x00, concat(voidRequest(1, 0), hex("00"))),
              "trailing");
          assertSw(0x6A80, transmit(0x84, 0x2E, 0x00, 0x00, tlv(0x80, u32(1))), "no reason");
          assertSw(0x6A86, transmit(0x84, 0x2E, 0x00, 0x01, voidRequest(1, 0)), "P2");
        });
    assertArrayEquals(head, chainHead(), "refusals change nothing");
  }

  @Test
  void voidOfALargeIssuanceNumberUsesTheJumpMaps() throws Exception {
    Params params = Params.variant(root, 5);
    personalize(params);
    // Advance issued to a large count without issuing: VOID requires seq <= issued, so issue
    // the quota and void the last one, then check the jump-ahead against the reference.
    for (int n = 0; n < 10; n++) issueOne();
    byte[][] response = voidOk(10, 1);
    assertEquals(referenceOpid(params, 10), new String(response[0], 70, 17, "US-ASCII"));
    assertEquals(
        reference(params).opidAt(10),
        new String(Arrays.copyOfRange(response[0], 70, 87), StandardCharsets.US_ASCII));
  }

  @Test
  void closeGatesIssuanceKeepsReportingAndIsIdempotent() throws Exception {
    Params params = Params.variant(root, 1);
    params.quota = 5;
    personalize(params);
    String first =
        IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issueOne().certificate));
    byte[] point = samPoint();
    byte[] head = chainHead();

    byte[][] closed = close();
    byte[] entry = closed[0];
    assertEquals(73, entry.length);
    assertEquals(0x06, entry[8]);
    assertArrayEquals(head, Arrays.copyOfRange(entry, 33, 65));
    assertArrayEquals(u32(1), Arrays.copyOfRange(entry, 65, 69));
    assertArrayEquals(u32(5), Arrays.copyOfRange(entry, 69, 73));
    assertTrue(verify(publicKey(point), entry, closed[1]));
    assertEquals((byte) 0xE1, lifecycle());

    // Idempotent: the stored entry with a fresh signature, and the chain does not move.
    byte[] closedHead = chainHead();
    byte[][] again = close();
    assertArrayEquals(entry, again[0]);
    assertTrue(verify(publicKey(point), again[0], again[1]));
    assertArrayEquals(closedHead, chainHead());

    // Refused in CLOSED.
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY in CLOSED");
          assertSw(0x6985, transmit(0x84, 0x84, 0x00, 0x00), "BEGIN in CLOSED");
          assertSw(0x6985, transmit(0x84, 0x2A, 0x00, 0xF9, new byte[4]), "ISSUE in CLOSED");
        });
    assertSw(
        0x6985,
        transmit(0x80, 0x32, 0, 0, root.topUp(tlvValue(status(), 0x8B), INITIAL_TS + 1, 1)),
        "TOP UP in CLOSED");

    // Allowed in CLOSED: signed STATUS, certificate, last entry, DECIPHER, VOID, CHANGE PIN.
    byte[] nonce = new byte[16];
    assertSw(0x9000, transmit(0x80, 0xCA, 0x01, 0x01, nonce), "signed STATUS");
    samCertificate();
    byte[][] last = entryAndSignature(collect(transmit(0x80, 0xCA, 0x00, 0x03), "LAST ENTRY"));
    assertArrayEquals(entry, last[0]);
    byte[] deciphered =
        withMockedScp(
            () -> {
              assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
              return collect(
                  transmit(0x84, 0x2C, 0x00, 0x00, tlv(0x80, first.getBytes())), "DECIPHER");
            });
    assertArrayEquals(u32(1), tlvValue(deciphered, 0x83));
    byte[][] voided = voidOk(1, 2);
    assertEquals(first, new String(voided[0], 70, 17, "US-ASCII"));
    // After a VOID the last entry is no longer the CLOSE entry; CLOSE still re-serves it.
    assertArrayEquals(entry, close()[0]);

    // TERMINATE moves CLOSED to TERMINATED.
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
          collect(transmit(0x84, 0xE6, 0x00, 0x00), "TERMINATE");
        });
    assertEquals(LC_TERMINATED, lifecycle());
    withMockedScp(
        () -> assertSw(0x6985, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY when terminated"));
  }

  @Test
  void closeRequiresOperationalSecureChannelAndPin() {
    Params params = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x6982, transmit(0x84, 0xE8, 0x00, 0x00), "no PIN before LOCK");
        });
    personalize(params);
    assertSw(0x6982, transmit(0x80, 0xE8, 0x00, 0x00), "plaintext");
    withMockedScp(() -> assertSw(0x6982, transmit(0x84, 0xE8, 0x00, 0x00), "no PIN"));
  }

  @Test
  void changeOperatorPinChecksTheOldPinAgainstTheRetryCounter() {
    Params params = Params.variant(root, 0);
    personalize(params);
    byte[] newPin = "24681357".getBytes();
    byte[] wrong = "00000000".getBytes();
    assertSw(
        0x6982,
        transmit(0x80, 0x24, 0x00, 0x81, concat(tlv(0x80, PIN), tlv(0x81, newPin))),
        "plaintext");
    withMockedScp(
        () -> {
          assertSw(
              0x63C4,
              transmit(0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, wrong), tlv(0x81, newPin))),
              "wrong old PIN");
          assertSw(
              0x6A80,
              transmit(0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, PIN), tlv(0x81, new byte[5]))),
              "short new PIN");
          assertSw(0x6A80, transmit(0x84, 0x24, 0x00, 0x81, tlv(0x80, PIN)), "missing new PIN");
          assertSw(
              0x9000,
              transmit(0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, PIN), tlv(0x81, newPin))),
              "change");
          assertSw(0x63C4, transmit(0x84, 0x20, 0x00, 0x81, PIN), "old PIN no longer valid");
          assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, newPin), "new PIN");
          for (int i = 0; i < 5; i++) {
            transmit(0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, wrong), tlv(0x81, newPin)));
          }
          assertSw(
              0x6983,
              transmit(0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, newPin), tlv(0x81, PIN))),
              "blocked");
        });
  }

  @Test
  void changeOperatorPinIsRefusedBeforeLock() {
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(
              0x6985,
              transmit(
                  0x84, 0x24, 0x00, 0x81, concat(tlv(0x80, PIN), tlv(0x81, "24681357".getBytes()))),
              "INSTALLED");
        });
  }
}
