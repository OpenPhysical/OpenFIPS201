/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.emulator;

import dev.mistial.tools.openfips201.common.CardTarget;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Deterministic owner-thread lifecycle for ZeroMQ emulator integration tests. */
public final class ZmqEmulatorFixture implements AutoCloseable {
  private static final long START_TIMEOUT_SECONDS = 5;
  private static final long STOP_TIMEOUT_SECONDS = 2;

  private final ZmqApduServer server;
  private final Thread serverThread;
  private final CompletableFuture<Void> terminated;
  private final String endpoint;
  private boolean closed;

  private ZmqEmulatorFixture(
      ZmqApduServer server,
      Thread serverThread,
      CompletableFuture<Void> terminated,
      String endpoint) {
    this.server = server;
    this.serverThread = serverThread;
    this.terminated = terminated;
    this.endpoint = endpoint;
  }

  public static ZmqEmulatorFixture start(byte[] scp03MasterKey) throws Exception {
    ZmqApduServer server = new ZmqApduServer(scp03MasterKey);
    CompletableFuture<String> ready = new CompletableFuture<>();
    CompletableFuture<Void> terminated = new CompletableFuture<>();
    Thread thread =
        new Thread(
            () -> {
              try {
                server.run("tcp://127.0.0.1:*", ready::complete);
                terminated.complete(null);
              } catch (Throwable failure) {
                ready.completeExceptionally(failure);
                terminated.completeExceptionally(failure);
              }
            },
            "openfips201-zmq-emulator");
    thread.start();
    try {
      String endpoint = ready.get(START_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      return new ZmqEmulatorFixture(server, thread, terminated, endpoint);
    } catch (InterruptedException failure) {
      Thread.currentThread().interrupt();
      server.stop();
      thread.join(TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS));
      server.close();
      throw new IllegalStateException("Interrupted while starting ZeroMQ emulator", failure);
    } catch (ExecutionException | TimeoutException failure) {
      server.stop();
      thread.join(TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS));
      server.close();
      throw new IllegalStateException("ZeroMQ emulator failed to start", unwrap(failure));
    }
  }

  public String endpoint() {
    return endpoint;
  }

  public CardTarget target() {
    return CardTarget.parse("zmq:" + endpoint);
  }

  @Override
  public void close() throws Exception {
    if (closed) {
      return;
    }
    closed = true;
    server.stop();
    serverThread.join(TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS));
    if (serverThread.isAlive()) {
      server.close();
      throw new IllegalStateException("ZeroMQ emulator did not stop within two seconds");
    }
    server.close();
    try {
      terminated.get();
    } catch (ExecutionException failure) {
      throw new IllegalStateException("ZeroMQ emulator serve loop failed", failure.getCause());
    }
  }

  private static Throwable unwrap(Exception failure) {
    return failure instanceof ExecutionException && failure.getCause() != null
        ? failure.getCause()
        : failure;
  }
}
