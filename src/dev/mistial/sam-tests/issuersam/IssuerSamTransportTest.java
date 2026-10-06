package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;

/** GENERATE TRANSPORT KEY and PUT PARAMETERS v5 key transport, end to end. */
class IssuerSamTransportTest extends IssuerSamTestSupport {

  private byte[] generateTransport() {
    ResponseAPDU response = transmit(0x84, 0x4A, 0x00, 0x00);
    assertSw(0x9000, response, "GENERATE TRANSPORT KEY");
    byte[] data = response.getData();
    assertEquals(67, data.length);
    assertEquals(0x86, data[0] & 0xFF);
    assertEquals(0x41, data[1] & 0xFF);
    return Arrays.copyOfRange(data, 2, 67);
  }

  @Test
  void wrappedKeyIsUnwrappedAndTheTransportKeyIsConsumed() {
    Params params = Params.variant(root, 1);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          params.transportPub = generateTransport();
          byte[] packet = params.encode();
          assertSw(0x9000, transmitChained(0x84, 0xD0, 0, 0, packet), "PUT v5");
          assertEquals(LC_PARAMS_SET, lifecycle());
          // The paramsDigest commits to the unwrapped key through its KCV.
          assertArrayEquals(
              referenceParamsDigest(params),
              tlvValue(collect(transmit(0x84, 0xCA, 0x00, 0x04), "PARAMS"), 0x93));
          // The transport key was destroyed: the same packet cannot be replayed.
          assertSw(0x6985, transmitChained(0x84, 0xD0, 0, 0, packet), "replay");
        });
  }

  @Test
  void issuanceUsesTheTransportedKey() throws Exception {
    Params params = Params.variant(root, 3);
    personalize(params);
    assertEquals(
        referenceOpid(params, 1),
        IssuerSamIssuanceTest.serialNumberOf(
            new org.bouncycastle.cert.X509CertificateHolder(issueOne().certificate)));
  }

  @Test
  void integrityAndBindingFailuresChangeNothing() {
    Params first = Params.variant(root, 0);
    withMockedScp(
        () -> {
          assertSw(0x9000, selectSam(), "SELECT");
          assertSw(0x9000, putParameters(first), "first PUT");
          byte[] digest = tlvValue(collect(transmit(0x84, 0xCA, 0x00, 0x04), "PARAMS"), 0x93);

          Params second = Params.variant(root, 2);
          // Tampered wrapped key: RFC 3394 integrity failure.
          second.transportPub = generateTransport();
          byte[] packet = second.encode();
          packet[packet.length - 1] ^= 0x01;
          assertSw(0x6A80, transmitChained(0x84, 0xD0, 0, 0, packet), "tampered wrap");
          // KEK derived for another IIN.
          second.kdfIinOverride = 4321;
          assertSw(0x6A80, transmitChained(0x84, 0xD0, 0, 0, second.encode()), "IIN not bound");
          second.kdfIinOverride = null;
          // Host ephemeral point off the curve.
          byte[] offCurve = point(newP256().getPublic());
          offCurve[64] ^= 0x01;
          second.hostEphOverride = offCurve;
          assertSw(0x6A80, transmitChained(0x84, 0xD0, 0, 0, second.encode()), "off-curve");
          second.hostEphOverride = null;
          // Wrapped to a superseded transport key: GENERATE replaces the pair.
          byte[] stale = second.transportPub;
          generateTransport();
          second.transportPub = stale;
          assertSw(0x6A80, transmitChained(0x84, 0xD0, 0, 0, second.encode()), "stale key");

          // None of the failures changed the stored parameters.
          assertEquals(LC_PARAMS_SET, lifecycle());
          assertArrayEquals(
              digest, tlvValue(collect(transmit(0x84, 0xCA, 0x00, 0x04), "PARAMS"), 0x93));
          assertArrayEquals(
              String.format("%04d", first.batch).getBytes(), tlvValue(status(), 0x83));
        });
  }

  @Test
  void transportKeyCommandAccessAndLifecycle() {
    Params params = Params.variant(root, 0);
    assertSw(0x9000, selectSam(), "SELECT");
    assertSw(0x6982, transmit(0x80, 0x4A, 0x00, 0x00), "plaintext");
    withMockedScp(
        () -> {
          assertSw(0x6A86, transmit(0x84, 0x4A, 0x00, 0x01), "P2");
          // PUT PARAMETERS without a transport key.
          assertSw(0x6985, transmitChained(0x84, 0xD0, 0, 0, params.encode()), "no transport");
          assertSw(0x9000, putParameters(params), "PUT");
          generateKey();
          assertSw(0x6985, transmit(0x84, 0x4A, 0x00, 0x00), "after GENERATE SAM KEY");
        });
    personalizeRest(params);
    withMockedScp(() -> assertSw(0x6985, transmit(0x84, 0x4A, 0x00, 0x00), "after LOCK"));
  }

  /** Completes personalization after PUT PARAMETERS and GENERATE SAM KEY. */
  private void personalizeRest(Params params) {
    withMockedScp(
        () -> {
          assertSw(0x9000, transmit(0x84, 0xD2, 0x00, 0x81, PIN), "PIN");
          byte[] point = generateKey();
          assertSw(
              0x9000,
              transmitChained(
                  0x84, 0xD4, 0, 0, root.issueSamCertificate(point, params, new SamCertSpec())),
              "LOAD");
          assertFalse(
              Arrays.equals(new byte[0], collect(transmit(0x84, 0xD6, 0x00, 0x00), "LOCK")));
        });
  }
}
