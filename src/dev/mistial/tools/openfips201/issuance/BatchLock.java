/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Exclusive lock on a batch ({@code batches/<b>/batch.lock}) held for one SAM or card operation, so
 * two processes never interleave SAM events, ledger lines or {@code batch.json} updates.
 */
public final class BatchLock implements AutoCloseable {
  private final FileChannel channel;
  private final FileLock lock;

  private BatchLock(FileChannel channel, FileLock lock) {
    this.channel = channel;
    this.lock = lock;
  }

  /** Acquires the lock without waiting; fails when another operation holds it. */
  public static BatchLock acquire(Path batchDirectory) throws IOException {
    Path file = batchDirectory.resolve("batch.lock");
    FileChannel channel;
    try {
      channel =
          FileChannel.open(
              file,
              java.util.EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE),
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    } catch (UnsupportedOperationException e) {
      channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    }
    FileLock lock;
    try {
      lock = channel.tryLock();
    } catch (OverlappingFileLockException e) {
      lock = null;
    }
    if (lock == null) {
      channel.close();
      throw new IllegalStateException(
          "Batch " + batchDirectory.getFileName() + " is in use by another operation");
    }
    return new BatchLock(channel, lock);
  }

  @Override
  public void close() throws IOException {
    try {
      lock.release();
    } finally {
      channel.close();
    }
  }
}
