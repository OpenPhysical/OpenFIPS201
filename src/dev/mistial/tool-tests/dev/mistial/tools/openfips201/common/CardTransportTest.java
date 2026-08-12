/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import apdu4j.core.BIBO;
import apdu4j.core.MockBIBO;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;

class CardTransportTest {
  @Test
  void enforcesExclusiveSequentialSessionOwnership() {
    BIBO bibo = MockBIBO.of();
    try (CardTransport transport = new CardTransport(bibo)) {
      assertSame(bibo, transport.bibo());
      assertSame(bibo, transport.acquireSession());
      assertThrows(IllegalStateException.class, transport::bibo);
      assertThrows(IllegalStateException.class, transport::acquireSession);

      transport.releaseSession();
      assertSame(bibo, transport.bibo());
    }
  }

  @Test
  void refusesCloseWhileSessionIsActive() {
    CardTransport transport = new CardTransport(MockBIBO.of());
    transport.acquireSession();

    assertThrows(IllegalStateException.class, transport::close);
    transport.releaseSession();
    assertDoesNotThrow(transport::close);
    assertDoesNotThrow(transport::close);
    assertThrows(IllegalStateException.class, transport::bibo);
  }

  @Test
  void rejectsCrossThreadUse() throws Exception {
    CardTransport transport = new CardTransport(MockBIBO.of());
    CompletableFuture<Throwable> result = new CompletableFuture<>();
    Thread thread =
        new Thread(
            () -> {
              try {
                transport.bibo();
                result.complete(null);
              } catch (Throwable failure) {
                result.complete(failure);
              }
            });
    thread.start();
    thread.join();

    Throwable failure = get(result);
    assertSame(IllegalStateException.class, failure.getClass());
    transport.close();
  }

  private static Throwable get(CompletableFuture<Throwable> result)
      throws InterruptedException, ExecutionException {
    return result.get();
  }
}
