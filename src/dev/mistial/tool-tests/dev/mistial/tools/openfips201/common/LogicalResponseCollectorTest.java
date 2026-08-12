package dev.mistial.tools.openfips201.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.ArrayDeque;
import java.util.Queue;
import org.junit.jupiter.api.Test;

class LogicalResponseCollectorTest {
  @Test
  void collectsAllFragmentsAndUsesRequestedContinuationClass() {
    QueueSession session = new QueueSession(response("03046102"), response("059000"));

    byte[] result =
        LogicalResponseCollector.collect(session, response("01026102"), 0x00, 5, "object");

    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, result);
    assertEquals(2, session.commands.size());
    assertEquals(0x00, session.commands.remove().getCLA());
    assertEquals(2, session.commands.remove().getNe());
  }

  @Test
  void maps6100ToLe256() {
    QueueSession session = new QueueSession(response("019000"));

    LogicalResponseCollector.collect(session, response("6100"), 0x0C, 1, "response");

    assertEquals(0x0C, session.commands.remove().getCLA());
    assertEquals(256, session.lastCommand.getNe());
  }

  @Test
  void rejectsOversizedAndFailedResponses() {
    assertThrows(
        IllegalStateException.class,
        () ->
            LogicalResponseCollector.collect(
                new QueueSession(), response("01029000"), 0x00, 1, "object"));
    assertThrows(
        IllegalStateException.class,
        () ->
            LogicalResponseCollector.collect(
                new QueueSession(), response("6982"), 0x00, 1, "object"));
  }

  private static ResponseAPDU response(String hex) {
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return new ResponseAPDU(bytes);
  }

  private static final class QueueSession implements CardSession {
    final Queue<ResponseAPDU> responses = new ArrayDeque<ResponseAPDU>();
    final Queue<CommandAPDU> commands = new ArrayDeque<CommandAPDU>();
    CommandAPDU lastCommand;

    QueueSession(ResponseAPDU... responses) {
      for (ResponseAPDU response : responses) this.responses.add(response);
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
      lastCommand = command;
      commands.add(command);
      return responses.remove();
    }

    @Override
    public void close() {}
  }
}
