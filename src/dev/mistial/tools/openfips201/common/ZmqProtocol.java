/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

/** Shared constants for the OpenFIPS201 APDU-over-ZeroMQ wire protocol. */
public final class ZmqProtocol {
  public static final String VERB_APDU = "APDU";
  public static final String VERB_RESET = "RESET";
  public static final String VERB_ATR = "ATR";
  public static final String VERB_PING = "PING";
  public static final String REPLY_OK = "OK";
  public static final String REPLY_ERR = "ERR";
  public static final String PING_RESPONSE = "OpenFIPS201-emulator";

  private ZmqProtocol() {}
}
