package dev.mistial.openphysical.sam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.Signature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * ISSUE commit ordering: every burn-point write happens inside the one transaction, the SAM signs
 * only after the commit, and an injected failure inside the transaction aborts it.
 */
class SamCommitOrderingTest {
  private AutoCloseable engineContext;

  @BeforeEach
  void enterEngine() throws Exception {
    engineContext = WhiteBox.engineContext();
  }

  @AfterEach
  void leaveEngine() throws Exception {
    engineContext.close();
  }

  /** Wraps the platform Signature so its calls can be observed in order. */
  private static Signature observedSignature(List<String> events, WhiteBox.Transactions tx) {
    Signature real = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    Signature wrapped = Mockito.mock(Signature.class, AdditionalAnswers.delegatesTo(real));
    Mockito.doAnswer(
            call -> {
              events.add("sign");
              assertEquals(0, tx.depth, "signing only outside the transaction");
              return call.getMethod().invoke(real, call.getArguments());
            })
        .when(wrapped)
        .signPreComputedHash(
            Mockito.any(byte[].class),
            Mockito.anyShort(),
            Mockito.anyShort(),
            Mockito.any(byte[].class),
            Mockito.anyShort());
    return wrapped;
  }

  @Test
  void writesHappenInsideTheTransactionAndSigningFollowsCommit() throws Exception {
    WhiteBox.Transactions tx = new WhiteBox.Transactions();
    Signature signature = observedSignature(tx.events, tx);
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class);
        MockedStatic<Signature> signatures =
            Mockito.mockStatic(Signature.class, Mockito.CALLS_REAL_METHODS)) {
      WhiteBox.mockTransientStorage(system);
      signatures
          .when(() -> Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false))
          .thenReturn(signature);
      WhiteBox.Fixture[] holder = new WhiteBox.Fixture[1];
      byte[][] atBegin = new byte[2][];
      byte[][] atCommit = new byte[2][];
      tx.install(
          system,
          () -> {
            atBegin[0] = holder[0].state.issued.clone();
            atBegin[1] = holder[0].state.chainHead.clone();
          },
          () -> {
            atCommit[0] = holder[0].state.issued.clone();
            atCommit[1] = holder[0].state.chainHead.clone();
          });
      WhiteBox.Fixture f = new WhiteBox.Fixture();
      holder[0] = f;
      byte[] x0 = f.state.lcgX.clone();

      short length = f.issue();

      assertEquals(0x70, f.io[0] & 0xFF, "response assembled");
      assertTrue(length > 400, "response assembled");
      assertEquals(Arrays.asList("begin", "commit", "sign", "sign"), tx.events);
      assertArrayEquals(new byte[4], atBegin[0], "issued untouched before the transaction");
      assertArrayEquals(new byte[32], atBegin[1], "chain untouched before the transaction");
      assertArrayEquals(U32Test.u32(1), atCommit[0], "issued written inside the transaction");
      assertFalse(Arrays.equals(new byte[32], atCommit[1]), "chain written inside");
      assertFalse(Arrays.equals(x0, f.state.lcgX), "x advanced");

      InOrder order = Mockito.inOrder(signature);
      order.verify(signature).init(f.crypto.samPrivate, Signature.MODE_SIGN);
      order
          .verify(signature, Mockito.times(2))
          .signPreComputedHash(
              Mockito.any(byte[].class),
              Mockito.anyShort(),
              Mockito.eq((short) 32),
              Mockito.any(byte[].class),
              Mockito.anyShort());
      // The TBS hash is signed as read back from the persistent last entry.
      Mockito.verify(signature)
          .signPreComputedHash(
              Mockito.same(f.state.lastEntry),
              Mockito.eq((short) (f.state.lastEntryLength - 32)),
              Mockito.eq((short) 32),
              Mockito.any(byte[].class),
              Mockito.anyShort());
      Mockito.verify(signature)
          .signPreComputedHash(
              Mockito.same(f.state.chainHead),
              Mockito.eq((short) 0),
              Mockito.eq((short) 32),
              Mockito.any(byte[].class),
              Mockito.anyShort());
    }
  }

  @Test
  void injectedFailureInsideTheTransactionAborts() throws Exception {
    WhiteBox.Transactions tx = new WhiteBox.Transactions();
    Signature signature = observedSignature(tx.events, tx);
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class);
        MockedStatic<Signature> signatures =
            Mockito.mockStatic(Signature.class, Mockito.CALLS_REAL_METHODS)) {
      WhiteBox.mockTransientStorage(system);
      signatures
          .when(() -> Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false))
          .thenReturn(signature);
      tx.install(system, () -> {}, () -> {});
      WhiteBox.Fixture f = new WhiteBox.Fixture();
      try (MockedStatic<Util> util = Mockito.mockStatic(Util.class, Mockito.CALLS_REAL_METHODS)) {
        util.when(
                () ->
                    Util.arrayCopy(
                        Mockito.any(byte[].class),
                        Mockito.anyShort(),
                        Mockito.same(f.state.lastEntry),
                        Mockito.anyShort(),
                        Mockito.anyShort()))
            .thenThrow(new TransactionException(TransactionException.BUFFER_FULL));
        assertThrows(TransactionException.class, f::issue);
      }
      assertEquals(Arrays.asList("begin", "abort"), tx.events);
      assertEquals(0, tx.depth);
      Mockito.verify(signature, Mockito.never())
          .signPreComputedHash(
              Mockito.any(byte[].class),
              Mockito.anyShort(),
              Mockito.anyShort(),
              Mockito.any(byte[].class),
              Mockito.anyShort());
    }
  }

  @Test
  void terminateClearsTheSamKeyAndTheFf1Key() throws Exception {
    WhiteBox.Transactions tx = new WhiteBox.Transactions();
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class)) {
      WhiteBox.mockTransientStorage(system);
      tx.install(system, () -> {}, () -> {});
      WhiteBox.Fixture f = new WhiteBox.Fixture();
      assertTrue(f.crypto.fpeKey.isInitialized());
      f.ledger.terminate();
      assertEquals(SamConst.LC_TERMINATED, f.state.lifecycle);
      assertFalse(f.crypto.fpeKey.isInitialized(), "FF1 key cleared");
      assertFalse(f.crypto.isSamKeyInitialized(), "SAM key cleared");
    }
  }

  @Test
  void capacityGuardStopsBeforeAnyTransaction() throws Exception {
    WhiteBox.Transactions tx = new WhiteBox.Transactions();
    try (MockedStatic<JCSystem> system = Mockito.mockStatic(JCSystem.class)) {
      WhiteBox.mockTransientStorage(system);
      tx.install(system, () -> {}, () -> {});
      WhiteBox.Fixture f = new WhiteBox.Fixture();

      // issued == quota
      System.arraycopy(U32Test.u32(10), 0, f.state.issued, 0, 4);
      assertFalse(f.state.hasCapacity());
      ISOException quota = assertThrows(ISOException.class, f::issue);
      assertEquals((short) 0x6A84, quota.getReason());

      // issued == m even with a larger (out-of-invariant) quota: the sequence never wraps.
      System.arraycopy(U32Test.u32(100_000_000L), 0, f.state.issued, 0, 4);
      System.arraycopy(U32Test.u32(200_000_000L), 0, f.state.quota, 0, 4);
      assertFalse(f.state.hasCapacity());
      f.newRequest();
      assertEquals((short) 0x6A84, assertThrows(ISOException.class, f::issue).getReason());

      // issued == m - 1 has exactly one left.
      System.arraycopy(U32Test.u32(99_999_999L), 0, f.state.issued, 0, 4);
      assertTrue(f.state.hasCapacity());
      assertTrue(tx.events.isEmpty(), "no transaction was opened");

      // The re-check inside the transaction refuses even if the pre-check was bypassed.
      System.arraycopy(U32Test.u32(10), 0, f.state.quota, 0, 4);
      System.arraycopy(U32Test.u32(10), 0, f.state.issued, 0, 4);
      ISOException inside =
          assertThrows(
              ISOException.class,
              () ->
                  f.state.commitIssue(
                      new byte[8],
                      (short) 0,
                      new byte[4],
                      (short) 0,
                      new byte[80],
                      (short) 0,
                      (short) 80,
                      new byte[32],
                      (short) 0));
      assertEquals((short) 0x6A84, inside.getReason());
      assertEquals(Arrays.asList("begin", "abort"), tx.events);
    }
  }
}
