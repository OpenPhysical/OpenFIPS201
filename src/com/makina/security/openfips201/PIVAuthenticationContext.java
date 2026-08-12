/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.JCSystem;

/** Owns transient GENERAL AUTHENTICATE state and guarantees complete reset zeroisation. */
final class PIVAuthenticationContext {
  private final byte[] state;

  PIVAuthenticationContext(short length) {
    state = JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
  }

  byte[] buffer() {
    return state;
  }

  void reset() {
    PIVSecurityProvider.zeroise(state, (short) 0, (short) state.length);
  }
}
