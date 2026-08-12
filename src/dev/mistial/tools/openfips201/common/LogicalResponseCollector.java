package dev.mistial.tools.openfips201.common;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.io.ByteArrayOutputStream;

/** Reassembles a bounded ISO 7816-4 response chain. */
public final class LogicalResponseCollector {
  private static final int MAX_FRAMES = 1024;

  private LogicalResponseCollector() {}

  public static byte[] collect(
      CardSession session,
      ResponseAPDU first,
      int continuationCla,
      int maximumLength,
      String label) {
    if (maximumLength < 0) throw new IllegalArgumentException("maximumLength must not be negative");
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ResponseAPDU current = first;
    int frames = 0;
    while (true) {
      if (++frames > MAX_FRAMES) {
        throw new IllegalStateException(label + " exceeded the response-chain frame limit");
      }
      byte[] fragment = current.getData();
      if (output.size() + fragment.length > maximumLength) {
        throw new IllegalStateException(label + " exceeded " + maximumLength + " bytes");
      }
      output.write(fragment, 0, fragment.length);
      if (current.getSW1() != 0x61) {
        if (current.getSW() != 0x9000) {
          throw new IllegalStateException(
              label + " failed SW=" + String.format("0x%04X", current.getSW()));
        }
        return output.toByteArray();
      }
      if (fragment.length == 0 && current.getSW2() == 0 && frames > 1) {
        throw new IllegalStateException(label + " returned a non-progressing response chain");
      }
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = session.transmit(new CommandAPDU(continuationCla, 0xC0, 0x00, 0x00, le));
    }
  }
}
