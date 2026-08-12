package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PIVPinCommandHandlerRetryTest {
  @Test
  void contactlessRetriesExcludeTheIntermediateReserve() {
    // SP 800-73-5 Part 2 Section 3.2.1 requires VERIFY to preserve the issuer's
    // contactless intermediate retry reserve.
    assertEquals(0, PIVPinCommandHandler.usableRetries((byte) 1, (byte) 1, true));
    assertEquals(3, PIVPinCommandHandler.usableRetries((byte) 4, (byte) 1, true));
    assertEquals(4, PIVPinCommandHandler.usableRetries((byte) 4, (byte) 1, false));
  }
}
