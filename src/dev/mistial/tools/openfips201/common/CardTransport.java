/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;

/** Workflow-scoped card transport with sequential session ownership. */
public final class CardTransport implements AutoCloseable {
  private final BIBO bibo;
  private final boolean ownsConnection;
  private final Thread ownerThread;
  private boolean open = true;
  private boolean sessionActive;

  CardTransport(BIBO bibo) {
    this(bibo, true);
  }

  private CardTransport(BIBO bibo, boolean ownsConnection) {
    this.bibo = bibo;
    this.ownsConnection = ownsConnection;
    this.ownerThread = Thread.currentThread();
  }

  /** Takes ownership of an already-open card connection. */
  public static CardTransport own(BIBO bibo) {
    if (bibo == null) {
      throw new IllegalArgumentException("card connection is required");
    }
    return new CardTransport(bibo, true);
  }

  /** Borrows an already-open card connection without closing it when this wrapper closes. */
  public static CardTransport borrow(BIBO bibo) {
    if (bibo == null) {
      throw new IllegalArgumentException("card connection is required");
    }
    return new CardTransport(bibo, false);
  }

  public BIBO bibo() {
    requireOwnerThread();
    requireOpen();
    if (sessionActive) {
      throw new IllegalStateException("A GlobalPlatform session already owns this card transport");
    }
    return bibo;
  }

  public GlobalPlatformSession openGlobalPlatformSession(byte[] aid, ScpConfig config)
      throws Exception {
    return GlobalPlatformSession.open(this, aid, config);
  }

  @Override
  public void close() {
    requireOwnerThread();
    if (!open) {
      return;
    }
    if (sessionActive) {
      throw new IllegalStateException("Cannot close a card transport with an active session");
    }
    open = false;
    if (ownsConnection) {
      bibo.close();
    }
  }

  BIBO acquireSession() {
    requireOwnerThread();
    requireOpen();
    if (sessionActive) {
      throw new IllegalStateException("Card transport supports one active session at a time");
    }
    sessionActive = true;
    return bibo;
  }

  void releaseSession() {
    requireOwnerThread();
    if (!sessionActive) {
      throw new IllegalStateException("Card transport has no active session");
    }
    sessionActive = false;
  }

  private void requireOpen() {
    if (!open) {
      throw new IllegalStateException("Card transport is closed");
    }
  }

  private void requireOwnerThread() {
    if (Thread.currentThread() != ownerThread) {
      throw new IllegalStateException("Card transport must be used by its creating thread");
    }
  }
}
