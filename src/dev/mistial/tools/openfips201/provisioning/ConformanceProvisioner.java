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

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.ScpConfig;
import java.io.PrintStream;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Provisions an OpenFIPS201 card (or ZMQ emulator) from a {@link ConformancePackage} over GlobalPlatform
 * SCP03, using the same administrative PUT DATA / CHANGE REFERENCE DATA model as a real issuer.
 *
 * <p>Does not personalise the applet lifecycle state (tag {@code 69}); leaves the card in the
 * pre-personalisation administrative state so subsequent admin operations remain available under
 * SCP. Callers that need the SELECTABLE→personalised transition can issue it separately.
 */
public final class ConformanceProvisioner {

  private static final int MAX_CHUNK = 0x80;
  private static final int CLA_CHAINING = 0x10;
  private static final byte ADMIN_KEY_REF = StandardCardProfile.ADMIN_KEY_REF;

  private ConformanceProvisioner() {}

  /** Result summary of a provision run. */
  public static final class ProvisionReport {
    public final String credentialId;
    public final int objectsCreated;
    public final int keysImported;
    public final List<String> steps;

    ProvisionReport(String credentialId, int objectsCreated, int keysImported, List<String> steps) {
      this.credentialId = credentialId;
      this.objectsCreated = objectsCreated;
      this.keysImported = keysImported;
      this.steps = steps;
    }
  }

  /**
   * Opens SCP03 against the PIV AID on {@code target} and applies {@code pkg}.
   *
   * @param target card or {@code zmq:} endpoint
   * @param scp SCP configuration (defaults to the GlobalPlatform test key when null)
   * @param pkg package produced by {@link IcamCardFolder} or another loader
   * @param log optional progress stream (may be null)
   */
  public static ProvisionReport provision(
      CardTarget target, ScpConfig scp, ConformancePackage pkg, PrintStream log) throws Exception {
    if (target == null) {
      throw new IllegalArgumentException("target is required");
    }
    if (pkg == null) {
      throw new IllegalArgumentException("package is required");
    }
    ScpConfig config = scp == null ? ScpConfig.defaultTestScp03() : scp;
    BIBO bibo = target.openBibo();
    try {
      return provision(bibo, config, pkg, log);
    } finally {
      try {
        bibo.close();
      } catch (Exception ignored) {
        // best-effort close
      }
    }
  }

  /** Provisions over an already-open BIBO transport. */
  public static ProvisionReport provision(
      BIBO bibo, ScpConfig scp, ConformancePackage pkg, PrintStream log) throws Exception {
    IcamCardFolder.ensureProvider();
    ScpConfig config = scp == null ? ScpConfig.defaultTestScp03() : scp;
    List<String> steps = new ArrayList<String>();
    PrintStream out = log == null ? new PrintStream(new java.io.OutputStream() {
      @Override
      public void write(int b) {
        // discard
      }
    }) : log;

    GPSession gp = GPSession.connect(bibo, new AID(GlobalPlatformSession.PIV_AID));
    PlaintextKeys keys = config.toPlaintextKeys();
    gp.openSecureChannel(
        keys,
        new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
        null,
        EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
    steps.add("Opened SCP03 to PIV AID");
    out.println("Opened SCP03 to PIV AID for credential " + pkg.credentialId);

    // PIN / PUK (administrative CHANGE REFERENCE DATA over SCP).
    expect(
        gp.transmit(
            new CommandAPDU(
                0x00, 0x24, 0xFF, StandardCardProfile.LOCAL_PIN_REF & 0xFF, pkg.pin)),
        "Set local PIN");
    steps.add("Set local PIN");
    expect(
        gp.transmit(
            new CommandAPDU(0x00, 0x24, 0xFF, StandardCardProfile.PUK_REF & 0xFF, pkg.puk)),
        "Set PUK");
    steps.add("Set PUK");

    // Management key 9B.
    expect(
        gp.transmit(
            new CommandAPDU(
                0x00, 0xDB, 0x3F, 0x00, StandardCardProfile.managementKeyDefinition(pkg.adminKeyAlg))),
        "Create management key 9B");
    expect(
        gp.transmit(
            new CommandAPDU(
                0x00,
                0x24,
                pkg.adminKeyAlg & 0xFF,
                ADMIN_KEY_REF & 0xFF,
                StandardCardProfile.keyUpdateData(pkg.adminKey))),
        "Import management key 9B");
    steps.add("Provisioned management key 9B");
    out.println("Provisioned management key 9B");

    int keysImported = 0;
    for (ConformancePackage.KeyMaterial key : pkg.keys) {
      createKey(gp, key);
      importPrivateKey(gp, key);
      keysImported++;
      steps.add(
          String.format(
              "Imported key %s (slot 0x%02X, alg 0x%02X)",
              key.label, key.slot & 0xFF, key.algorithm & 0xFF));
      out.println(
          String.format(
              "Imported key %s (slot 0x%02X, alg 0x%02X)",
              key.label, key.slot & 0xFF, key.algorithm & 0xFF));
    }

    int objectsCreated = 0;
    for (ConformancePackage.DataObject object : pkg.dataObjects) {
      createDataObject(gp, object);
      putDataObject(gp, object);
      objectsCreated++;
      steps.add("Wrote object " + object.label + " (" + hexId(object.id) + ")");
      out.println(
          "Wrote object "
              + object.label
              + " ("
              + hexId(object.id)
              + ", "
              + object.payload.length
              + " bytes)");
    }

    out.println(
        "Provisioning complete: "
            + objectsCreated
            + " objects, "
            + keysImported
            + " keys from "
            + pkg.credentialId);
    return new ProvisionReport(pkg.credentialId, objectsCreated, keysImported, steps);
  }

  private static void createKey(GPSession gp, ConformancePackage.KeyMaterial key) {
    byte[] definition =
        AdminTlv.tlv(
            0x66,
            AdminTlv.concat(
                AdminTlv.tlv(0x8B, new byte[] {key.slot}),
                AdminTlv.tlv(0x8C, new byte[] {key.modeContact}),
                AdminTlv.tlv(0x8D, new byte[] {key.modeContactless}),
                AdminTlv.tlv(0x8E, new byte[] {key.algorithm}),
                AdminTlv.tlv(0x8F, new byte[] {key.role}),
                AdminTlv.tlv(0x90, new byte[] {key.attributes})));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, definition)),
        "Create key " + key.label);
  }

  private static void importPrivateKey(GPSession gp, ConformancePackage.KeyMaterial key)
      throws Exception {
    if (key.privateKey instanceof RSAPrivateKey) {
      importRsa(gp, key);
    } else if (key.privateKey instanceof ECPrivateKey) {
      importEcc(gp, key);
    } else {
      throw new IllegalArgumentException(
          "Unsupported private key type for " + key.label + ": " + key.privateKey.getClass());
    }
  }

  private static void importRsa(GPSession gp, ConformancePackage.KeyMaterial key) throws Exception {
    RSAPrivateKey privateKey = (RSAPrivateKey) key.privateKey;
    RSAPublicKey publicKey = (RSAPublicKey) key.certificate.getPublicKey();
    int modulusLength = modulusByteLength(key.algorithm);
    byte[] modulus = AdminTlv.fixed(publicKey.getModulus(), modulusLength);
    byte[] publicExponent = AdminTlv.fixed(publicKey.getPublicExponent(), 3);
    byte[] privateExponent = AdminTlv.fixed(privateKey.getPrivateExponent(), modulusLength);

    sendChained(
        gp,
        0x24,
        key.algorithm & 0xFF,
        key.slot & 0xFF,
        AdminTlv.tlv(0x30, AdminTlv.tlv(0x81, modulus)),
        "Import RSA modulus for " + key.label);
    sendChained(
        gp,
        0x24,
        key.algorithm & 0xFF,
        key.slot & 0xFF,
        AdminTlv.tlv(0x30, AdminTlv.tlv(0x82, publicExponent)),
        "Import RSA public exponent for " + key.label);
    sendChained(
        gp,
        0x24,
        key.algorithm & 0xFF,
        key.slot & 0xFF,
        AdminTlv.tlv(0x30, AdminTlv.tlv(0x83, privateExponent)),
        "Import RSA private exponent for " + key.label);
  }

  private static void importEcc(GPSession gp, ConformancePackage.KeyMaterial key) throws Exception {
    ECPrivateKey privateKey = (ECPrivateKey) key.privateKey;
    if (!(key.certificate.getPublicKey() instanceof ECPublicKey)) {
      throw new IllegalStateException("Certificate public key is not EC for " + key.label);
    }
    ECPublicKey publicKey = (ECPublicKey) key.certificate.getPublicKey();
    int coordLength = coordByteLength(key.algorithm);
    byte[] publicPoint = encodeUncompressedPoint(publicKey, coordLength);
    byte[] privateScalar = AdminTlv.fixed(privateKey.getS(), coordLength);

    sendChained(
        gp,
        0x24,
        key.algorithm & 0xFF,
        key.slot & 0xFF,
        AdminTlv.tlv(0x30, AdminTlv.tlv(0x86, publicPoint)),
        "Import ECC public point for " + key.label);
    sendChained(
        gp,
        0x24,
        key.algorithm & 0xFF,
        key.slot & 0xFF,
        AdminTlv.tlv(0x30, AdminTlv.tlv(0x87, privateScalar)),
        "Import ECC private scalar for " + key.label);
  }

  private static void createDataObject(GPSession gp, ConformancePackage.DataObject object) {
    byte[] definition =
        AdminTlv.tlv(
            0x64,
            AdminTlv.concat(
                AdminTlv.tlv(0x8B, object.id),
                AdminTlv.tlv(0x8C, new byte[] {object.modeContact}),
                AdminTlv.tlv(0x8D, new byte[] {object.modeContactless}),
                AdminTlv.tlv(0x91, new byte[] {ADMIN_KEY_REF})));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, definition)),
        "Create object " + object.label);
  }

  private static void putDataObject(GPSession gp, ConformancePackage.DataObject object) {
    byte[] payload;
    if (object.putForm == ConformancePackage.PutForm.DISCOVERY) {
      // Discovery is addressed as the raw 7E object (file already begins with 7E for ICAM).
      payload = object.payload;
      if (payload.length == 0 || (payload[0] & 0xFF) != 0x7E) {
        payload = AdminTlv.tlv(0x7E, object.payload);
      }
    } else {
      payload =
          AdminTlv.concat(AdminTlv.tlv(0x5C, object.id), AdminTlv.tlv(0x53, object.payload));
    }
    sendChained(gp, 0xDB, 0x3F, 0xFF, payload, "PUT DATA " + object.label);
  }

  private static void sendChained(
      GPSession gp, int ins, int p1, int p2, byte[] payload, String context) {
    int offset = 0;
    while (offset < payload.length) {
      int chunkLength = Math.min(MAX_CHUNK, payload.length - offset);
      byte[] chunk = new byte[chunkLength];
      System.arraycopy(payload, offset, chunk, 0, chunkLength);
      offset += chunkLength;
      int cla = offset < payload.length ? CLA_CHAINING : 0x00;
      expect(gp.transmit(new CommandAPDU(cla, ins, p1, p2, chunk)), context);
    }
  }

  private static ResponseAPDU expect(ResponseAPDU response, String context) {
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          String.format("%s failed with SW 0x%04X", context, response.getSW()));
    }
    return response;
  }

  private static int modulusByteLength(byte algorithm) {
    if (algorithm == IcamCardFolder.ALG_RSA_1024) {
      return 128;
    }
    if (algorithm == IcamCardFolder.ALG_RSA_2048) {
      return 256;
    }
    throw new IllegalArgumentException("Not an RSA algorithm: 0x" + Integer.toHexString(algorithm & 0xFF));
  }

  private static int coordByteLength(byte algorithm) {
    if (algorithm == IcamCardFolder.ALG_ECC_P256) {
      return 32;
    }
    if (algorithm == IcamCardFolder.ALG_ECC_P384) {
      return 48;
    }
    throw new IllegalArgumentException("Not an ECC algorithm: 0x" + Integer.toHexString(algorithm & 0xFF));
  }

  private static byte[] encodeUncompressedPoint(ECPublicKey publicKey, int coordLength) {
    byte[] x = AdminTlv.fixed(publicKey.getW().getAffineX(), coordLength);
    byte[] y = AdminTlv.fixed(publicKey.getW().getAffineY(), coordLength);
    byte[] out = new byte[1 + coordLength * 2];
    out[0] = 0x04;
    System.arraycopy(x, 0, out, 1, coordLength);
    System.arraycopy(y, 0, out, 1 + coordLength, coordLength);
    return out;
  }

  private static String hexId(byte[] id) {
    StringBuilder sb = new StringBuilder();
    for (byte b : id) {
      sb.append(String.format("%02X", b & 0xFF));
    }
    return sb.toString();
  }
}
