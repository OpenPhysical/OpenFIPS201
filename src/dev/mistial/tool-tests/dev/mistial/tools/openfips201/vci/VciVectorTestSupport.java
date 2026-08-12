package dev.mistial.tools.openfips201.vci;

import dev.mistial.tools.openfips201.common.ByteArrays;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Wire-level replay support shared by the v1 and v2 VCI fixture schemas.
 *
 * <p>The JSON layouts differ, but they describe the same APDU exchanges and secure-messaging state.
 * Keeping transport reassembly and C-MAC chaining here prevents either schema suite from silently
 * acquiring different protocol behavior.
 */
abstract class VciVectorTestSupport {
  protected static List<Exchange> reassembleTransportChains(List<Exchange> exchanges) {
    List<Exchange> merged = new ArrayList<>();
    List<byte[]> pending = new ArrayList<>();

    for (Exchange exchange : exchanges) {
      CapturedCommand command = CapturedCommand.parse(exchange.command);
      if (command.cla == 0x1C) {
        pending.add(command.data);
        continue;
      }
      if (!pending.isEmpty() && command.cla == 0x0C) {
        byte[][] parts = new byte[pending.size() + 1][];
        for (int i = 0; i < pending.size(); i++) {
          parts[i] = pending.get(i);
        }
        parts[pending.size()] = command.data;
        byte[] payload = ByteArrays.concat(parts);
        merged.add(exchange.reassembled(command.withData(payload)));
        pending.clear();
        continue;
      }

      // An unrelated command terminates an incomplete capture chain. It must not absorb stale
      // chunks from a malformed or truncated fixture.
      pending.clear();
      merged.add(exchange);
    }
    return merged;
  }

  protected static final class SmState {
    final byte[] counter;
    final byte[] cmdMcv;
    final byte[] respMcv;

    SmState(byte[] counter, byte[] cmdMcv, byte[] respMcv) {
      this.counter = counter;
      this.cmdMcv = cmdMcv;
      this.respMcv = respMcv;
    }
  }

  protected static final class Exchange {
    final String description;
    final byte[] command;
    final byte[] response;
    final int sw;
    final byte[] plainCommand;
    final byte[] plainResponse;
    final SmState stateBefore;
    final SmState stateAfterWrap;
    final SmState stateAfterUnwrap;

    Exchange(
        String description,
        byte[] command,
        byte[] response,
        int sw,
        byte[] plainCommand,
        byte[] plainResponse) {
      this(description, command, response, sw, plainCommand, plainResponse, null, null, null);
    }

    Exchange(
        String description,
        byte[] command,
        byte[] response,
        int sw,
        byte[] plainCommand,
        byte[] plainResponse,
        SmState stateBefore,
        SmState stateAfterWrap,
        SmState stateAfterUnwrap) {
      this.description = description;
      this.command = command;
      this.response = response;
      this.sw = sw;
      this.plainCommand = plainCommand;
      this.plainResponse = plainResponse;
      this.stateBefore = stateBefore;
      this.stateAfterWrap = stateAfterWrap;
      this.stateAfterUnwrap = stateAfterUnwrap;
    }

    private Exchange reassembled(byte[] reassembledCommand) {
      String base = description;
      int suffix = base.toLowerCase(Locale.ROOT).lastIndexOf(" [transport");
      if (suffix > 0) {
        base = base.substring(0, suffix);
      }
      return new Exchange(
          base + " (reassembled)",
          reassembledCommand,
          response,
          sw,
          plainCommand,
          plainResponse,
          stateBefore,
          stateAfterWrap,
          stateAfterUnwrap);
    }
  }

  /** Parsed case-3/case-4 command shape used by captured SM traffic. */
  private static final class CapturedCommand {
    final int cla;
    final byte ins;
    final byte p1;
    final byte p2;
    final byte[] data;
    final byte[] le;

    private CapturedCommand(int cla, byte ins, byte p1, byte p2, byte[] data, byte[] le) {
      this.cla = cla;
      this.ins = ins;
      this.p1 = p1;
      this.p2 = p2;
      this.data = data;
      this.le = le;
    }

    static CapturedCommand parse(byte[] encoded) {
      if (encoded == null || encoded.length < 5) {
        throw new IllegalArgumentException("Captured command has no Lc field");
      }
      boolean extended = (encoded[4] & 0xFF) == 0 && encoded.length > 7;
      int dataOffset = extended ? 7 : 5;
      int dataLength =
          extended ? ((encoded[5] & 0xFF) << 8) | (encoded[6] & 0xFF) : encoded[4] & 0xFF;
      int dataEnd = dataOffset + dataLength;
      if (dataEnd > encoded.length) {
        throw new IllegalArgumentException("Captured command data is truncated");
      }
      return new CapturedCommand(
          encoded[0] & 0xFF,
          encoded[1],
          encoded[2],
          encoded[3],
          Arrays.copyOfRange(encoded, dataOffset, dataEnd),
          Arrays.copyOfRange(encoded, dataEnd, encoded.length));
    }

    byte[] withData(byte[] payload) {
      byte[] encodedLe = le.length > 0 ? le : new byte[] {0x00};
      if (payload.length <= 255) {
        return ByteArrays.concat(
            new byte[] {0x0C, ins, p1, p2, (byte) payload.length}, payload, encodedLe);
      }
      if (le.length < 2) {
        encodedLe = new byte[] {0x01, 0x00};
      }
      return ByteArrays.concat(
          new byte[] {
            0x0C, ins, p1, p2, 0x00, (byte) (payload.length >>> 8), (byte) payload.length
          },
          payload,
          encodedLe);
    }
  }
}
