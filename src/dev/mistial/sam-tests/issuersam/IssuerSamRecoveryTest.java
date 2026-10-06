package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.openphysical.sam.IssuerSam;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import javacard.security.CryptoException;
import javacard.security.Signature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Failure after the issuance commit: the OPID is burned (6500), GET LAST ENTRY recovers the signed
 * entry, and the next ISSUE receives the next OPID.
 *
 * <p>jCardEngine does not roll back persistent writes on {@code abortTransaction}, so tear and
 * abort behaviour is covered by the white-box commit-ordering tests instead of an end-to-end tear.
 */
class IssuerSamRecoveryTest extends IssuerSamTestSupport {
  private final AtomicBoolean failNextHashSignature = new AtomicBoolean();

  /**
   * Installs the SAM with its single Signature wrapped so a post-commit failure can be injected.
   */
  @Override
  protected void installApplet() {
    Signature real = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    Signature wrapped = Mockito.mock(Signature.class, AdditionalAnswers.delegatesTo(real));
    Mockito.doAnswer(
            invocation -> {
              if (failNextHashSignature.getAndSet(false)) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
              }
              return invocation.getMethod().invoke(real, invocation.getArguments());
            })
        .when(wrapped)
        .signPreComputedHash(
            Mockito.any(byte[].class),
            Mockito.anyShort(),
            Mockito.anyShort(),
            Mockito.any(byte[].class),
            Mockito.anyShort());
    try (MockedStatic<Signature> mocked =
        Mockito.mockStatic(Signature.class, Mockito.CALLS_REAL_METHODS)) {
      mocked
          .when(() -> Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false))
          .thenReturn(wrapped);
      engine.installApplet(SAM_AID, IssuerSam.class, new byte[0]);
    }
  }

  @Test
  void failureAfterCommitBurnsTheOpidAndIsRecoverable() throws Exception {
    Params params = Params.variant(root, 6);
    personalize(params);
    byte[] samPoint = samCertificate().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

    KeyPair f9 = newP256();
    int sw =
        withMockedScp(
            () -> {
              assertSw(0x9000, transmit(0x84, 0x20, 0x00, 0x81, PIN), "VERIFY");
              byte[] nonce = beginIssuance();
              failNextHashSignature.set(true);
              return issueResponse(f9, nonce, defaultValidity()).getSW();
            });
    assertEquals(0x6500, sw, "failure after commit");
    assertEquals(1, issued(), "the OPID is burned");

    byte[][] last = entryAndSignature(collect(transmit(0x80, 0xCA, 0x00, 0x03), "LAST ENTRY"));
    byte[] entry = last[0];
    assertTrue(verify(publicKey(samPoint), entry, last[1]), "fresh signature over the entry");
    assertArrayEquals(sha256(entry), chainHead());
    String burned = referenceOpid(params, 1);
    assertEquals(burned, new String(entry, 70, entry[69], "US-ASCII"));
    int skiOffset = 70 + entry[69];
    assertArrayEquals(
        ski(point(f9.getPublic())), Arrays.copyOfRange(entry, skiOffset, skiOffset + 20));
    withMockedScp(() -> assertSw(0x6985, transmit(0x84, 0xCA, 0x00, 0x05), "no LAST RESULT"));

    Issued next = issueOne();
    assertEquals(
        referenceOpid(params, 2),
        IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(next.certificate)));
    assertArrayEquals(sha256(entry), Arrays.copyOfRange(next.entry, 33, 65), "chain continues");
  }
}
