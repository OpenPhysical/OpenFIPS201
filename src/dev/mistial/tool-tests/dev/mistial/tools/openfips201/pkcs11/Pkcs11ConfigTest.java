/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.mistial.tools.openfips201.common.SecureFiles;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Pkcs11ConfigTest {
  @TempDir Path temp;

  @Test
  void ownerOnlyPinFileIsReadWithoutTrailingNewline() throws Exception {
    Path pin =
        SecureFiles.writeNew(temp.resolve("pin"), "123456\n".getBytes(StandardCharsets.UTF_8));
    Pkcs11Config config = new Pkcs11Config();
    config.pinFile = pin.toString();

    assertArrayEquals("123456".toCharArray(), config.readPin());
  }

  @Test
  void groupReadablePinFileIsRefused() throws Exception {
    Assumptions.assumeTrue(SecureFiles.isPosix(temp), "POSIX file system required");
    Path pin = temp.resolve("pin");
    Files.write(pin, "123456".getBytes(StandardCharsets.UTF_8));
    Files.setPosixFilePermissions(pin, PosixFilePermissions.fromString("rw-r-----"));
    Pkcs11Config config = new Pkcs11Config();
    config.pinFile = pin.toString();

    assertThrows(RuntimeException.class, config::readPin);
  }

  @Test
  void missingPinSourceIsRefused() {
    assertThrows(IllegalArgumentException.class, () -> new Pkcs11Config().readPin());
  }

  @Test
  void copyKeepsPinPrompt() {
    Pkcs11Config config = new Pkcs11Config();
    config.pinPrompt = true;
    assertEquals(true, config.copy().pinPrompt);
  }

  @Test
  void tokenLabelIsBlankPaddedToThirtyTwoBytes() {
    byte[] padded = Pkcs11Token.paddedLabel("p1");
    assertEquals(32, padded.length);
    assertEquals('p', padded[0]);
    assertEquals('1', padded[1]);
    for (int i = 2; i < padded.length; i++) {
      assertEquals(' ', padded[i]);
    }
    assertThrows(
        IllegalArgumentException.class,
        () -> Pkcs11Token.paddedLabel("012345678901234567890123456789012"));
  }
}
