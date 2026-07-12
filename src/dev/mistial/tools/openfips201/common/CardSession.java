/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;

public interface CardSession extends AutoCloseable {
  ResponseAPDU transmit(CommandAPDU command);

  @Override
  void close();
}
