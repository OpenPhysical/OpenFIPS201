/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.provisioning;

/**
 * The single, deterministic definition of a standard OpenFIPS201 test card.
 *
 * <p>The applet generates a random PIN and PUK at boot, so any consumer that needs a known card
 * must provision it. This class is the one source of truth for what a standard test card contains
 * and is shared by both the JUnit harness (which applies it over a mocked GlobalPlatform secure
 * channel) and the emulator provisioning (which applies it over a real SCP03 channel), so a test
 * card is set up the same way everywhere. It holds transport-agnostic constants and payload
 * builders only; callers attach the appropriate APDU transport.
 */
public final class StandardCardProfile {

  /** PIV Card Application local PIN reference. */
  public static final byte LOCAL_PIN_REF = (byte) 0x80;

  /** PIV Card Application PUK reference. */
  public static final byte PUK_REF = (byte) 0x81;

  /** Card management key reference (9B). */
  public static final byte ADMIN_KEY_REF = (byte) 0x9B;

  /** Card management key mechanism: AES-128. */
  public static final byte ADMIN_KEY_ALG = (byte) 0x08;

  /** Local PIN "123456", padded to the 8-byte card-interface block with 0xFF. */
  public static final byte[] PIN = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, (byte) 0xFF, (byte) 0xFF};

  /** PUK "12345678". */
  public static final byte[] PUK = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  /** Card management (9B) key, AES-128, fixed for deterministic tests. */
  public static final byte[] ADMIN_KEY = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
  };

  /**
   * Fixed 16-byte GUID used as the secure-messaging CVC (C_ICC) subject identifier, so the
   * emulator's card identity is deterministic instead of a fresh random value per provisioning.
   */
  public static final byte[] CVC_SUBJECT = {
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    (byte) 0x88,
    (byte) 0x99,
    (byte) 0xAA,
    (byte) 0xBB,
    (byte) 0xCC,
    (byte) 0xDD,
    (byte) 0xEE,
    (byte) 0xFF
  };

  private StandardCardProfile() {}

  /**
   * Wraps a key value in the {@code 30 len 80 len <key>} structure expected by the administrative
   * CHANGE REFERENCE DATA key-import command.
   */
  public static byte[] keyUpdateData(byte[] keyBytes) {
    byte[] out = new byte[4 + keyBytes.length];
    out[0] = (byte) 0x30;
    out[1] = (byte) (keyBytes.length + 2);
    out[2] = (byte) 0x80;
    out[3] = (byte) keyBytes.length;
    System.arraycopy(keyBytes, 0, out, 4, keyBytes.length);
    return out;
  }

  /**
   * Returns the {@code 0x66} object definition for the card management key (9B) with the given PIV
   * mechanism (e.g. {@link #ADMIN_KEY_ALG} for AES-128, or a 3DES/AES-192/AES-256 identifier).
   */
  public static byte[] managementKeyDefinition(byte algorithm) {
    return new byte[] {
      (byte) 0x66,
      (byte) 0x12,
      (byte) 0x8B,
      (byte) 0x01,
      ADMIN_KEY_REF,
      (byte) 0x8C,
      (byte) 0x01,
      (byte) 0x7F,
      (byte) 0x8D,
      (byte) 0x01,
      (byte) 0x00,
      (byte) 0x8E,
      (byte) 0x01,
      algorithm,
      (byte) 0x8F,
      (byte) 0x01,
      (byte) 0x01,
      (byte) 0x90,
      (byte) 0x01,
      (byte) 0x11
    };
  }
}
