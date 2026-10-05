/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureFilesTest {
  @TempDir Path temp;

  private final ByteArrayOutputStream warnings = new ByteArrayOutputStream();
  private PrintStream previousWarnings;

  @BeforeEach
  void requirePosix() throws Exception {
    Assumptions.assumeTrue(SecureFiles.isPosix(temp), "POSIX file system required");
    previousWarnings = SecureFiles.warnings(new PrintStream(warnings, true, "UTF-8"));
  }

  @AfterEach
  void restoreWarnings() {
    SecureFiles.warnings(previousWarnings);
  }

  @Test
  void createdDirectoriesAreOwnerOnlyImmediately() throws Exception {
    Path home = temp.resolve("home");
    Path nested = home.resolve("producers").resolve("p1");

    SecureFiles.createPrivateDirectories(home, nested);

    assertEquals("rwx------", mode(home));
    assertEquals("rwx------", mode(home.resolve("producers")));
    assertEquals("rwx------", mode(nested));
  }

  @Test
  void writeNewIsOwnerOnlyAndRefusesAnExistingFile() throws Exception {
    Path file = temp.resolve("secret.pin");

    SecureFiles.writeNew(file, "first".getBytes(StandardCharsets.UTF_8));

    assertEquals("rw-------", mode(file));
    assertThrows(
        FileAlreadyExistsException.class,
        () -> SecureFiles.writeNew(file, "second".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals("first".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
  }

  @Test
  void replaceAtomicallyLeavesNoTemporaryFile() throws Exception {
    Path file = temp.resolve("producer.json");
    SecureFiles.writeNew(file, "old".getBytes(StandardCharsets.UTF_8));

    SecureFiles.replaceAtomically(file, "new".getBytes(StandardCharsets.UTF_8));

    assertArrayEquals("new".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    assertEquals("rw-------", mode(file));
    try (Stream<Path> entries = Files.list(temp)) {
      assertEquals(1, entries.count(), "only the replaced file remains");
    }
  }

  @Test
  void appendLineCreatesOwnerOnlyFileAndAppends() throws Exception {
    Path csv = temp.resolve("receipts.csv");

    SecureFiles.appendLine(csv, "a");
    SecureFiles.appendLine(csv, "b\n");

    assertEquals("a\nb\n", new String(Files.readAllBytes(csv), StandardCharsets.UTF_8));
    assertEquals("rw-------", mode(csv));
  }

  @Test
  void refusesGroupWritableHome() throws Exception {
    Path home = Files.createDirectory(temp.resolve("home"));
    Files.setPosixFilePermissions(home, PosixFilePermissions.fromString("rwxrwxr-x"));

    assertThrows(
        IOException.class,
        () -> SecureFiles.createPrivateDirectories(home, home.resolve("producers")));
    assertTrue(!Files.exists(home.resolve("producers")), "nothing is created below a refused home");
  }

  @Test
  void tightensReadableHomeWithWarning() throws Exception {
    Path home = Files.createDirectory(temp.resolve("home"));
    Files.setPosixFilePermissions(home, PosixFilePermissions.fromString("rwxr-xr-x"));

    SecureFiles.createPrivateDirectories(home, home.resolve("producers"));

    assertEquals("rwx------", mode(home));
    assertTrue(new String(warnings.toByteArray(), StandardCharsets.UTF_8).contains("tightened"));
  }

  @Test
  void requireOwnerOnlyRefusesGroupReadableFile() throws Exception {
    Path file = temp.resolve("key.hex");
    Files.write(file, "00".getBytes(StandardCharsets.UTF_8));
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----"));

    assertThrows(IOException.class, () -> SecureFiles.requireOwnerOnly(file));

    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    SecureFiles.requireOwnerOnly(file);
  }

  private static String mode(Path path) throws IOException {
    return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
  }
}
