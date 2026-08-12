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

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.common.ApduSupport;
import dev.mistial.tools.openfips201.common.CardConnectionFactory;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.LogicalResponseCollector;
import dev.mistial.tools.openfips201.common.PlainPivSession;
import dev.mistial.tools.openfips201.common.ScpConfig;
import java.io.PrintStream;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import pro.javacard.gp.GPSession;

/**
 * Provisions an OpenFIPS201 card (or ZMQ emulator) from a {@link ConformancePackage} over
 * GlobalPlatform SCP03, using the same administrative PUT DATA / CHANGE REFERENCE DATA model as a
 * real issuer.
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
    return provision((CardConnectionFactory) target, scp, pkg, log);
  }

  /**
   * Confirms that the live card matches the public portion of a declared personalization profile.
   * This preflight never verifies a PIN, so selecting the wrong profile cannot consume retries.
   */
  public static void verifyPublicProfile(CardConnectionFactory connections, ConformancePackage pkg)
      throws Exception {
    try (PlainPivSession piv = PlainPivSession.open(connections, GlobalPlatformSession.PIV_AID)) {
      int checked = 0;
      for (ConformancePackage.DataObject object : pkg.dataObjects) {
        if (object.modeContact != IcamCardFolder.ACCESS_ALWAYS) continue;
        byte[] expected =
            object.putForm == ConformancePackage.PutForm.DISCOVERY
                ? object.payload
                : AdminTlv.tlv(0x53, object.payload);
        byte[] actual = getData(piv, object.id, expected.length);
        if (!Arrays.equals(expected, actual)) {
          throw new IllegalStateException(
              "Physical card does not match profile "
                  + pkg.credentialId
                  + " at "
                  + object.label
                  + " ("
                  + hexId(object.id)
                  + ")");
        }
        checked++;
      }
      if (checked == 0) {
        throw new IllegalArgumentException("Profile has no public objects to verify");
      }
      verifyManagementMechanism(piv, pkg);
    }
  }

  private static void verifyManagementMechanism(PlainPivSession piv, ConformancePackage pkg) {
    int algorithm =
        pkg.managementKey == null
            ? StandardCardProfile.ADMIN_KEY_ALG & 0xFF
            : pkg.managementKey.algorithm & 0xFF;
    ResponseAPDU response =
        piv.transmit(
            new CommandAPDU(
                0x00,
                0x87,
                algorithm,
                ADMIN_KEY_REF & 0xFF,
                new byte[] {0x7C, 0x02, (byte) 0x81, 0x00}));
    if (pkg.managementKey == null) {
      // SP 800-73-5 Part 2, Section 3.2.4 assigns 6A86 to an unsupported P2. Any other response
      // proves that a profile claiming SCP-only administration does not match the live card.
      if (response.getSW() != 0x6A86) {
        throw new IllegalStateException(
            String.format(
                "Physical card unexpectedly exposes management key 9B (SW %04X)",
                response.getSW()));
      }
    } else if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          String.format(
              "Physical card does not expose declared management key 9B (SW %04X)",
              response.getSW()));
    }
  }

  /** Provisions through SCP03, then verifies through a fresh plain PIV connection. */
  public static ProvisionReport provision(
      CardConnectionFactory connections, ScpConfig scp, ConformancePackage pkg, PrintStream log)
      throws Exception {
    if (connections == null) throw new IllegalArgumentException("connections are required");
    if (pkg == null) throw new IllegalArgumentException("package is required");
    ScpConfig config = scp == null ? ScpConfig.defaultTestScp03() : scp;
    ProvisionReport report;
    try (CardTransport transport = CardTransport.own(connections.open());
        GlobalPlatformSession administrative =
            transport.openGlobalPlatformSession(GlobalPlatformSession.PIV_AID, config)) {
      report = provisionAdministrative(administrative.gp(), pkg, log);
    }
    try {
      verifyReadback(connections, pkg, log, report.steps);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Provisioning writes were committed, but plain PIV readback failed; the applet was not"
              + " personalized",
          e);
    }
    return report;
  }

  /** Validates, provisions, and only then performs the irreversible lifecycle transition. */
  public static ProvisionReport provisionCertificationProfile(
      CardTarget target,
      ScpConfig scp,
      ConformancePackage pkg,
      CertificationProfileValidator.Claims claims,
      PrintStream log)
      throws Exception {
    CertificationProfileValidator.validate(pkg, claims);
    ProvisionReport report = provision(target, scp, pkg, log);
    personalize(target, scp);
    return report;
  }

  private static void personalize(CardTarget target, ScpConfig scp) throws Exception {
    if (target == null) throw new IllegalArgumentException("target is required");
    ScpConfig config = scp == null ? ScpConfig.defaultTestScp03() : scp;
    try (GlobalPlatformSession administrative =
        GlobalPlatformSession.open(target, GlobalPlatformSession.PIV_AID, config)) {
      // Proprietary admin PUT DATA operation 69 has an empty value.
      expect(
          administrative.transmit(
              new CommandAPDU(0x80, 0xDB, 0xFF, 0xFF, AdminTlv.tlv(0x69, new byte[0]))),
          "Personalize validated certification profile");
    }
  }

  /** Applies administrative mutations over an already-open SCP-capable transport. */
  private static ProvisionReport provisionAdministrative(
      GPSession gp, ConformancePackage pkg, PrintStream log) throws Exception {
    IcamCardFolder.ensureProvider();
    List<String> steps = new ArrayList<String>();
    PrintStream out =
        log == null
            ? new PrintStream(
                new java.io.OutputStream() {
                  @Override
                  public void write(int b) {
                    // discard
                  }
                })
            : log;

    steps.add("Opened SCP03 to PIV AID");
    out.println("Opened SCP03 to PIV AID for credential " + pkg.credentialId);

    // PIN / PUK (administrative CHANGE REFERENCE DATA over SCP).
    expect(
        gp.transmit(
            new CommandAPDU(0x80, 0x24, 0x01, StandardCardProfile.LOCAL_PIN_REF & 0xFF, pkg.pin)),
        "Set local PIN");
    steps.add("Set local PIN");
    expect(
        gp.transmit(new CommandAPDU(0x80, 0x24, 0x01, StandardCardProfile.PUK_REF & 0xFF, pkg.puk)),
        "Set PUK");
    steps.add("Set PUK");

    // SP 800-73 permits administration through an authenticated card-management key or through
    // the issuer's secure channel. Do not invent 9B material for an ICAM package that has none.
    if (pkg.managementKey != null) {
      expect(
          gp.transmit(
              new CommandAPDU(
                  0x80,
                  0xDB,
                  0xFF,
                  0xFF,
                  StandardCardProfile.managementKeyDefinition(pkg.managementKey.algorithm))),
          "Create management key 9B");
      expect(
          gp.transmit(
              new CommandAPDU(
                  0x80,
                  0x25,
                  0x01,
                  ADMIN_KEY_REF & 0xFF,
                  adminKeyUpdateData(
                      pkg.managementKey.algorithm,
                      StandardCardProfile.keyUpdateData(pkg.managementKey.key)))),
          "Import management key 9B");
      steps.add("Provisioned management key 9B");
      out.println("Provisioned management key 9B");
    } else {
      steps.add("Management restricted to SCP (no 9B material supplied)");
      out.println("No management key supplied; administration remains SCP-only");
    }

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

  private static void verifyReadback(
      CardConnectionFactory connections,
      ConformancePackage pkg,
      PrintStream log,
      List<String> steps)
      throws Exception {
    PrintStream out =
        log == null
            ? new PrintStream(
                new java.io.OutputStream() {
                  @Override
                  public void write(int b) {
                    // discard
                  }
                })
            : log;
    try (PlainPivSession piv = PlainPivSession.open(connections, GlobalPlatformSession.PIV_AID)) {
      byte[] pinBlock = new byte[8];
      Arrays.fill(pinBlock, (byte) 0xFF);
      System.arraycopy(pkg.pin, 0, pinBlock, 0, Math.min(pkg.pin.length, pinBlock.length));
      expect(
          piv.transmit(
              new CommandAPDU(
                  0x00, 0x20, 0x00, StandardCardProfile.LOCAL_PIN_REF & 0xFF, pinBlock)),
          "Verify local PIN for object readback");

      for (ConformancePackage.DataObject object : pkg.dataObjects) {
        byte[] expected =
            object.putForm == ConformancePackage.PutForm.DISCOVERY
                ? object.payload
                : AdminTlv.tlv(0x53, object.payload);
        byte[] actual = getData(piv, object.id, expected.length);
        if (!Arrays.equals(expected, actual)) {
          throw new IllegalStateException(
              "Readback mismatch for "
                  + object.label
                  + " ("
                  + hexId(object.id)
                  + "): expected "
                  + expected.length
                  + " bytes, got "
                  + actual.length);
        }
      }
      steps.add("Verified exact readback of " + pkg.dataObjects.size() + " data objects");
      out.println("Verified exact readback of " + pkg.dataObjects.size() + " data objects");
    }
  }

  private static byte[] getData(PlainPivSession piv, byte[] objectId, int maximumLength) {
    ResponseAPDU response =
        piv.transmit(new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, AdminTlv.tlv(0x5C, objectId), 256));
    return LogicalResponseCollector.collect(
        piv, response, 0x00, maximumLength, "Read back object " + hexId(objectId));
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
        gp.transmit(new CommandAPDU(0x80, 0xDB, 0xFF, 0xFF, definition)),
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
        0x25,
        0x01,
        key.slot & 0xFF,
        adminKeyUpdateData(key.algorithm, AdminTlv.tlv(0x30, AdminTlv.tlv(0x81, modulus))),
        "Import RSA modulus for " + key.label);
    sendChained(
        gp,
        0x25,
        0x01,
        key.slot & 0xFF,
        adminKeyUpdateData(key.algorithm, AdminTlv.tlv(0x30, AdminTlv.tlv(0x82, publicExponent))),
        "Import RSA public exponent for " + key.label);
    sendChained(
        gp,
        0x25,
        0x01,
        key.slot & 0xFF,
        adminKeyUpdateData(key.algorithm, AdminTlv.tlv(0x30, AdminTlv.tlv(0x83, privateExponent))),
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
        0x25,
        0x01,
        key.slot & 0xFF,
        adminKeyUpdateData(key.algorithm, AdminTlv.tlv(0x30, AdminTlv.tlv(0x86, publicPoint))),
        "Import ECC public point for " + key.label);
    sendChained(
        gp,
        0x25,
        0x01,
        key.slot & 0xFF,
        adminKeyUpdateData(key.algorithm, AdminTlv.tlv(0x30, AdminTlv.tlv(0x87, privateScalar))),
        "Import ECC private scalar for " + key.label);
  }

  private static void createDataObject(GPSession gp, ConformancePackage.DataObject object) {
    int capacity = CertificationProfileValidator.requiredCapacity(object.id, object.payload.length);
    byte[] definition =
        AdminTlv.tlv(
            0x64,
            AdminTlv.concat(
                AdminTlv.tlv(0x8B, object.id),
                AdminTlv.tlv(0x8C, new byte[] {object.modeContact}),
                AdminTlv.tlv(0x8D, new byte[] {object.modeContactless}),
                AdminTlv.tlv(0x91, new byte[] {ADMIN_KEY_REF}),
                AdminTlv.tlv(0x92, new byte[] {(byte) (capacity >> 8), (byte) capacity})));
    expect(
        gp.transmit(new CommandAPDU(0x80, 0xDB, 0xFF, 0xFF, definition)),
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
      payload = AdminTlv.concat(AdminTlv.tlv(0x5C, object.id), AdminTlv.tlv(0x53, object.payload));
    }
    sendChained(gp, 0xDB, 0x3F, 0xFF, payload, "PUT DATA " + object.label);
  }

  private static void sendChained(
      GPSession gp, int ins, int p1, int p2, byte[] payload, String context) {
    int baseCla = ins == 0x25 ? 0x80 : 0x00;
    ApduSupport.sendChained(gp::transmit, baseCla, ins, p1, p2, payload, MAX_CHUNK, context);
  }

  private static byte[] adminKeyUpdateData(byte algorithm, byte[] keyElement) {
    return AdminTlv.concat(AdminTlv.tlv(0x80, new byte[] {algorithm}), keyElement);
  }

  private static ResponseAPDU expect(ResponseAPDU response, String context) {
    return ApduSupport.expectSuccess(response, context);
  }

  private static int modulusByteLength(byte algorithm) {
    if (algorithm == IcamCardFolder.ALG_RSA_1024) {
      return 128;
    }
    if (algorithm == IcamCardFolder.ALG_RSA_2048) {
      return 256;
    }
    throw new IllegalArgumentException(
        "Not an RSA algorithm: 0x" + Integer.toHexString(algorithm & 0xFF));
  }

  private static int coordByteLength(byte algorithm) {
    if (algorithm == IcamCardFolder.ALG_ECC_P256) {
      return 32;
    }
    if (algorithm == IcamCardFolder.ALG_ECC_P384) {
      return 48;
    }
    throw new IllegalArgumentException(
        "Not an ECC algorithm: 0x" + Integer.toHexString(algorithm & 0xFF));
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
