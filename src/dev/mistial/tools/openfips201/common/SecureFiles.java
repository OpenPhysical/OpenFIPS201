/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.Set;

/**
 * Owner-only file and directory creation for issuer state.
 *
 * <p>Contract: on a POSIX file system every directory created here has mode 0700 and every file has
 * mode 0600 from the moment it exists (the mode is applied as a creation attribute, never by a
 * later chmod). Existing directories are accepted only when owned by the current user and not
 * group- or world-writable; an owner-only-writable directory with group/other read or search bits
 * is tightened to 0700 with a warning. On a non-POSIX file system the permission checks cannot be
 * expressed; a warning is printed once and the operations proceed without them.
 */
public final class SecureFiles {
  private static final Set<PosixFilePermission> DIRECTORY_MODE =
      PosixFilePermissions.fromString("rwx------");
  private static final Set<PosixFilePermission> FILE_MODE =
      PosixFilePermissions.fromString("rw-------");
  private static final Set<PosixFilePermission> GROUP_OR_OTHER_WRITE =
      EnumSet.of(PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);
  private static final Set<PosixFilePermission> GROUP_OR_OTHER =
      EnumSet.of(
          PosixFilePermission.GROUP_READ,
          PosixFilePermission.GROUP_WRITE,
          PosixFilePermission.GROUP_EXECUTE,
          PosixFilePermission.OTHERS_READ,
          PosixFilePermission.OTHERS_WRITE,
          PosixFilePermission.OTHERS_EXECUTE);

  private static volatile PrintStream warnings = System.err;
  private static volatile boolean nonPosixWarned;

  private SecureFiles() {}

  /** Redirects warnings, for callers and tests that capture diagnostics. */
  public static PrintStream warnings(PrintStream stream) {
    PrintStream previous = warnings;
    warnings = stream == null ? System.err : stream;
    return previous;
  }

  /**
   * Creates {@code directory} and every missing ancestor with mode 0700, and validates {@code
   * directory} itself when it already exists.
   *
   * @return {@code directory}
   */
  public static Path createPrivateDirectories(Path directory) throws IOException {
    Path absolute = directory.toAbsolutePath().normalize();
    if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
      requirePrivateDirectory(absolute);
      return directory;
    }
    Deque<Path> missing = new ArrayDeque<Path>();
    for (Path current = absolute;
        current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS);
        current = current.getParent()) {
      missing.push(current);
    }
    for (Path component : missing) {
      createPrivateDirectory(component);
    }
    return directory;
  }

  /**
   * Creates {@code directory} below {@code base}: every missing component from {@code base}
   * (inclusive) down to {@code directory} is created with mode 0700, and every existing component
   * in that range is validated with {@link #requirePrivateDirectory(Path)}. Ancestors of {@code
   * base} are outside this contract.
   *
   * @return {@code directory}
   */
  public static Path createPrivateDirectories(Path base, Path directory) throws IOException {
    Path absoluteBase = base.toAbsolutePath().normalize();
    Path absolute = directory.toAbsolutePath().normalize();
    if (!absolute.startsWith(absoluteBase)) {
      throw new IllegalArgumentException("directory is not below its private base: " + directory);
    }
    if (!Files.exists(absoluteBase, LinkOption.NOFOLLOW_LINKS)) {
      createPrivateDirectories(absoluteBase);
    }
    Deque<Path> components = new ArrayDeque<Path>();
    for (Path current = absolute;
        current != null && current.startsWith(absoluteBase);
        current = current.getParent()) {
      components.push(current);
    }
    for (Path component : components) {
      if (Files.exists(component, LinkOption.NOFOLLOW_LINKS)) {
        requirePrivateDirectory(component);
      } else {
        createPrivateDirectory(component);
      }
    }
    return directory;
  }

  private static void createPrivateDirectory(Path component) throws IOException {
    if (!isPosix(component)) {
      warnNonPosix(component);
      Files.createDirectory(component);
      return;
    }
    Files.createDirectory(component, PosixFilePermissions.asFileAttribute(DIRECTORY_MODE));
    // The umask can only clear bits of the creation attribute; restore exactly rwx------.
    Files.setPosixFilePermissions(component, DIRECTORY_MODE);
  }

  /**
   * Validates an existing directory: it must be a real directory owned by the current user and not
   * group- or world-writable. Group/other read or search bits are removed with a warning.
   */
  public static void requirePrivateDirectory(Path directory) throws IOException {
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("not a directory (or a symbolic link): " + directory);
    }
    PosixFileAttributes attributes = posixAttributes(directory);
    if (attributes == null) {
      warnNonPosix(directory);
      return;
    }
    requireCurrentOwner(directory, attributes.owner());
    Set<PosixFilePermission> permissions = attributes.permissions();
    if (!java.util.Collections.disjoint(permissions, GROUP_OR_OTHER_WRITE)) {
      throw new IOException(
          "refusing group- or world-writable directory "
              + directory
              + " (mode "
              + PosixFilePermissions.toString(permissions)
              + "); restrict it to the owner (chmod 700)");
    }
    if (!java.util.Collections.disjoint(permissions, GROUP_OR_OTHER)) {
      Files.setPosixFilePermissions(directory, DIRECTORY_MODE);
      warnings.println(
          "Warning: tightened "
              + directory
              + " from "
              + PosixFilePermissions.toString(permissions)
              + " to rwx------");
    }
  }

  /**
   * Requires {@code file} to be a regular file owned by the current user with no group or other
   * permission bits. Fails closed on POSIX file systems; warns on non-POSIX file systems.
   */
  public static void requireOwnerOnly(Path file) throws IOException {
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("not a regular file (or a symbolic link): " + file);
    }
    PosixFileAttributes attributes = posixAttributes(file);
    if (attributes == null) {
      warnNonPosix(file);
      return;
    }
    requireCurrentOwner(file, attributes.owner());
    if (!java.util.Collections.disjoint(attributes.permissions(), GROUP_OR_OTHER)) {
      throw new IOException(
          "refusing secret file "
              + file
              + " with mode "
              + PosixFilePermissions.toString(attributes.permissions())
              + "; it must be owner-only (chmod 600)");
    }
  }

  /**
   * Creates {@code file}, which must not exist, with mode 0600, writes {@code content}, forces it
   * to stable storage, and makes a best-effort fsync of the parent directory.
   */
  public static Path writeNew(Path file, byte[] content) throws IOException {
    writeCreateNew(file, content);
    syncDirectory(parentOf(file));
    return file;
  }

  /**
   * Replaces {@code file} (or creates it) atomically: the content is written to a 0600 temporary
   * file in the same directory, forced, then moved over {@code file} with {@code ATOMIC_MOVE}. No
   * temporary file remains on success or failure.
   */
  public static Path replaceAtomically(Path file, byte[] content) throws IOException {
    Path directory = parentOf(file);
    Path temp = directory.resolve("." + file.getFileName() + "." + randomSuffix() + ".tmp");
    try {
      writeCreateNew(temp, content);
      try {
        Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } catch (AtomicMoveNotSupportedException e) {
        throw new IOException("atomic replace is not supported for " + file, e);
      }
    } finally {
      Files.deleteIfExists(temp);
    }
    syncDirectory(directory);
    return file;
  }

  /**
   * Appends {@code line} to {@code file} under an exclusive {@link FileChannel#lock()}, then forces
   * it. A missing file is created with mode 0600.
   */
  public static Path appendLine(Path file, String line) throws IOException {
    boolean created = !Files.exists(file, LinkOption.NOFOLLOW_LINKS);
    Set<StandardOpenOption> options =
        EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
    byte[] bytes = (line.endsWith("\n") ? line : line + "\n").getBytes(StandardCharsets.UTF_8);
    try (FileChannel channel = FileChannel.open(file, options, fileAttributes(file));
        FileLock ignored = channel.lock()) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes);
      while (buffer.hasRemaining()) {
        channel.write(buffer);
      }
      channel.force(true);
    }
    if (created) {
      syncDirectory(parentOf(file));
    }
    return file;
  }

  /** Reports whether POSIX permissions are enforced for {@code path}'s file store. */
  public static boolean isPosix(Path path) {
    Path probe = path.toAbsolutePath();
    while (probe != null && !Files.exists(probe)) {
      probe = probe.getParent();
    }
    if (probe == null) {
      return false;
    }
    return Files.getFileAttributeView(probe, PosixFileAttributeView.class) != null;
  }

  private static void writeCreateNew(Path file, byte[] content) throws IOException {
    Set<StandardOpenOption> options =
        EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
    try (FileChannel channel = FileChannel.open(file, options, fileAttributes(file))) {
      if (isPosix(file)) {
        // The umask can only clear bits of the creation attribute; restore exactly rw-------
        // before any content is written.
        Files.setPosixFilePermissions(file, FILE_MODE);
      }
      ByteBuffer buffer = ByteBuffer.wrap(content);
      while (buffer.hasRemaining()) {
        channel.write(buffer);
      }
      channel.force(true);
    } catch (FileAlreadyExistsException e) {
      throw new FileAlreadyExistsException(file.toString(), null, "refusing to overwrite");
    }
  }

  private static FileAttribute<?>[] fileAttributes(Path file) {
    if (isPosix(parentOf(file))) {
      return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(FILE_MODE)};
    }
    warnNonPosix(file);
    return new FileAttribute<?>[0];
  }

  private static void syncDirectory(Path directory) {
    // Best effort: directory fsync makes the new entry durable on POSIX systems; other platforms
    // reject opening a directory for reading, which is not an error for this contract.
    try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
      channel.force(true);
    } catch (IOException | RuntimeException ignored) {
      // Durability of the directory entry is best effort by contract.
    }
  }

  private static PosixFileAttributes posixAttributes(Path path) throws IOException {
    PosixFileAttributeView view =
        Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
    return view == null ? null : view.readAttributes();
  }

  private static void requireCurrentOwner(Path path, UserPrincipal owner) throws IOException {
    UserPrincipal current =
        path.getFileSystem()
            .getUserPrincipalLookupService()
            .lookupPrincipalByName(System.getProperty("user.name"));
    if (!current.equals(owner)) {
      throw new IOException("refusing " + path + " owned by " + owner.getName());
    }
  }

  private static Path parentOf(Path file) {
    Path parent = file.toAbsolutePath().getParent();
    if (parent == null) {
      throw new IllegalArgumentException("file has no parent directory: " + file);
    }
    return parent;
  }

  private static String randomSuffix() {
    byte[] random = new byte[8];
    new SecureRandom().nextBytes(random);
    return HexUtil.format(random);
  }

  private static void warnNonPosix(Path path) {
    if (!nonPosixWarned) {
      nonPosixWarned = true;
      warnings.println(
          "Warning: "
              + path
              + " is on a file system without POSIX permissions; owner-only access is not"
              + " enforced");
    }
  }
}
