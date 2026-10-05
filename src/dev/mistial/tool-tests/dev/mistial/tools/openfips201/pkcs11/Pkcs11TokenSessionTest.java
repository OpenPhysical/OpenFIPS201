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

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Session lifecycle of {@link Pkcs11Token#open(CryptokiLibrary, Pkcs11Config)}. */
class Pkcs11TokenSessionTest {
  private static final long CKR_PIN_INCORRECT = 0xA0;
  private static final long SESSION = 42;

  @Test
  void loginFailureClosesTheOpenedSession() {
    RecordingLibrary recording = new RecordingLibrary(CKR_PIN_INCORRECT);
    Pkcs11Config config = config();
    config.pinEnv = "PATH";

    assertThrows(Pkcs11Exception.class, () -> Pkcs11Token.open(recording.library(), config));
    assertEquals(1, recording.opened);
    assertEquals(1, recording.closed.size());
    assertEquals(SESSION, recording.closed.get(0).longValue());
  }

  @Test
  void pinRetrievalFailureClosesTheOpenedSession() {
    RecordingLibrary recording = new RecordingLibrary(Pkcs11Constants.CKR_OK);
    Pkcs11Config config = config();
    config.pinEnv = "OPENFIPS201_TEST_PIN_THAT_IS_NEVER_SET";

    assertThrows(
        IllegalArgumentException.class, () -> Pkcs11Token.open(recording.library(), config));
    assertEquals(1, recording.opened);
    assertEquals(1, recording.closed.size());
  }

  @Test
  void pinIsEncodedAsUtf8WithoutLoss() {
    // LATIN SMALL LETTER E WITH ACUTE encodes to two UTF-8 bytes.
    char[] pin = {'1', '2', (char) 0xE9, '3', '4'};
    assertArrayEquals(
        new String(pin).getBytes(StandardCharsets.UTF_8), Pkcs11Token.encodeUtf8(pin.clone()));
  }

  private static Pkcs11Config config() {
    Pkcs11Config config = new Pkcs11Config();
    config.module = "unused";
    config.slot = 0;
    return config;
  }

  private static final class RecordingLibrary {
    private final long loginResult;
    int opened;
    final List<Long> closed = new ArrayList<Long>();

    RecordingLibrary(long loginResult) {
      this.loginResult = loginResult;
    }

    CryptokiLibrary library() {
      return (CryptokiLibrary)
          Proxy.newProxyInstance(
              CryptokiLibrary.class.getClassLoader(),
              new Class<?>[] {CryptokiLibrary.class},
              (proxy, method, args) -> {
                String name = method.getName();
                if ("C_OpenSession".equals(name)) {
                  opened++;
                  ((NativeLongByReference) args[4]).setValue(new NativeLong(SESSION));
                  return new NativeLong(Pkcs11Constants.CKR_OK);
                }
                if ("C_Login".equals(name)) {
                  return new NativeLong(loginResult);
                }
                if ("C_CloseSession".equals(name)) {
                  closed.add(((NativeLong) args[0]).longValue());
                  return new NativeLong(Pkcs11Constants.CKR_OK);
                }
                throw new UnsupportedOperationException(name);
              });
    }
  }
}
