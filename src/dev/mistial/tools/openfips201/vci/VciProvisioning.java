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

package dev.mistial.tools.openfips201.vci;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayOutputStream;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.EnumSet;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Implements the VCI provisioning and probe flows for {@link VciTool}.
 *
 * <p>Provisioning follows the same administrative model as a real card: every card-content change
 * travels over a GlobalPlatform SCP03 secure channel, the SM key pair is generated on-card (the
 * private key never leaves it), and the host only signs the card's public key into a CVC.
 */
final class VciProvisioning {

  private static final byte[] PIV_AID = Hex.decode("A000000308000010000100");
  private static final byte[] PAIRING_OBJECT_ID = {(byte) 0x5F, (byte) 0xC1, (byte) 0x23};
  private static final byte[][] INSPECTION_OBJECT_SWEEP = {
    Hex.decode("5FC102"),
    Hex.decode("5FC105"),
    Hex.decode("5FC103"),
    Hex.decode("5FC106"),
    Hex.decode("5FC108"),
    Hex.decode("5FC101"),
    Hex.decode("5FC10A"),
    Hex.decode("5FC10B"),
    Hex.decode("5FC109"),
    Hex.decode("5FC10C"),
    Hex.decode("5FC10D"),
    Hex.decode("5FC10E"),
    Hex.decode("5FC10F"),
    Hex.decode("5FC110"),
    Hex.decode("5FC111"),
    Hex.decode("5FC112"),
    Hex.decode("5FC113"),
    Hex.decode("5FC114"),
    Hex.decode("5FC115"),
    Hex.decode("5FC116"),
    Hex.decode("5FC117"),
    Hex.decode("5FC118"),
    Hex.decode("5FC119"),
    Hex.decode("5FC11A"),
    Hex.decode("5FC11B"),
    Hex.decode("5FC11C"),
    Hex.decode("5FC11D"),
    Hex.decode("5FC11E"),
    Hex.decode("5FC11F"),
    Hex.decode("5FC120"),
    Hex.decode("5FC121"),
    Hex.decode("7F61")
  };
  private static final byte[] SM_SIGNER_OBJECT_ID = {(byte) 0x5F, (byte) 0xC1, (byte) 0x22};
  private static final int MAX_CHUNK = 0x80;
  private static final int CLA_CHAINING = 0x10;
  private static final byte ACCESS_ALWAYS = (byte) 0x7F;
  // Access-mode bits matching the applet's PIVObject bitmap: PIN (0x01) and VCI (0x08).
  private static final byte ACCESS_PIN = (byte) 0x01;
  private static final byte ACCESS_VCI = (byte) 0x08;
  private static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;
  private static final byte ATTR_NONE = (byte) 0x00;

  private VciProvisioning() {}

  // ---------------------------------------------------------------------------------------------
  // CA management
  // ---------------------------------------------------------------------------------------------

  static void ensureProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static CaMaterial makeCa(String outPrefix, String subjectDn) throws Exception {
    return makeCa(outPrefix, subjectDn, VciSupport.ALG_CS2);
  }

  /** Creates a VCI signer CA on the curve matching the cipher suite (P-256 or P-384). */
  static CaMaterial makeCa(String outPrefix, String subjectDn, byte suite) throws Exception {
    ensureProvider();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(VciSupport.namedCurve(suite)), new SecureRandom());
    KeyPair keyPair = generator.generateKeyPair();

    X500Name subject = new X500Name(subjectDn);
    BigInteger serial = new BigInteger(160, new SecureRandom()).abs();
    java.util.Date notBefore = new java.util.Date();
    java.util.Date notAfter =
        new java.util.Date(notBefore.getTime() + 10L * 365 * 24 * 60 * 60 * 1000);
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
    ContentSigner signer =
        new JcaContentSignerBuilder(VciSupport.cvcSignatureAlgorithm(suite))
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.getPrivate());
    X509CertificateHolder holder = builder.build(signer);
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(holder);

    if (outPrefix != null) {
      writePem(Paths.get(outPrefix + ".key"), keyPair.getPrivate());
      writePem(Paths.get(outPrefix + ".crt"), certificate);
    }
    return new CaMaterial(keyPair.getPrivate(), certificate);
  }

  static CaMaterial loadCa(String certPath, String keyPath) throws Exception {
    ensureProvider();
    X509Certificate certificate = readCertificate(Paths.get(certPath));
    PrivateKey privateKey = readPrivateKey(Paths.get(keyPath));
    return new CaMaterial(privateKey, certificate);
  }

  static final class CaMaterial {
    final PrivateKey privateKey;
    final X509Certificate certificate;

    CaMaterial(PrivateKey privateKey, X509Certificate certificate) {
      this.privateKey = privateKey;
      this.certificate = certificate;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Provisioning (over GlobalPlatform SCP03)
  // ---------------------------------------------------------------------------------------------

  static void provision(
      BIBO bibo,
      String caCertPath,
      String caKeyPath,
      String caOutPrefix,
      String pairingCode,
      String scp03KeyHex)
      throws Exception {
    provision(bibo, caCertPath, caKeyPath, caOutPrefix, pairingCode, scp03KeyHex, VciSupport.ALG_CS2);
  }

  /**
   * Provisions VCI SM key + CVC + pairing for the given cipher suite ({@link VciSupport#ALG_CS2} or
   * {@link VciSupport#ALG_CS7}).
   */
  static void provision(
      BIBO bibo,
      String caCertPath,
      String caKeyPath,
      String caOutPrefix,
      String pairingCode,
      String scp03KeyHex,
      byte suite)
      throws Exception {
    requirePairingCode(pairingCode);
    if (!VciSupport.isCs2(suite) && !VciSupport.isCs7(suite)) {
      throw new IllegalArgumentException("suite must be CS2 (0x27) or CS7 (0x2E)");
    }

    CaMaterial ca;
    if (caCertPath != null && caKeyPath != null) {
      ca = loadCa(caCertPath, caKeyPath);
    } else if (caOutPrefix != null) {
      ca = makeCa(caOutPrefix, "CN=OpenFIPS201 VCI Signer", suite);
      System.out.println(
          "Generated VCI signer CA: " + caOutPrefix + ".key / " + caOutPrefix + ".crt");
    } else {
      throw new IllegalArgumentException("Supply --ca-cert/--ca-key or --ca-out");
    }

    byte[] scpKey =
        scp03KeyHex == null
            ? PlaintextKeys.DEFAULT_KEY()
            : Hex.decode(scp03KeyHex.replace(" ", ""));
    GPSession gp = GPSession.connect(bibo, new AID(PIV_AID));
    PlaintextKeys keys = PlaintextKeys.fromMasterKey(scpKey);
    keys.setVersion(0);
    gp.openSecureChannel(
        keys,
        new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0),
        null,
        EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));

    // STEP 0 - Set the deterministic standard-card PIN and PUK (administrative CHANGE REFERENCE
    // DATA
    // over SCP). The applet boots with a random PIN/PUK, so without this the emulator card has an
    // unknown PIN; using the shared profile keeps it identical to the JUnit standard test card.
    expect(
        gp.transmit(
            new CommandAPDU(
                0x00,
                0x24,
                0xFF,
                StandardCardProfile.LOCAL_PIN_REF & 0xFF,
                StandardCardProfile.PIN)),
        "Set standard local PIN");
    expect(
        gp.transmit(
            new CommandAPDU(
                0x00, 0x24, 0xFF, StandardCardProfile.PUK_REF & 0xFF, StandardCardProfile.PUK)),
        "Set standard PUK");

    // STEP 1 - Define the SM key: reference 04, CS2/CS7, key-establishment role, non-importable.
    byte[] keyDefinition =
        VciSupport.tlv(
            0x66,
            concat(
                VciSupport.tlv(0x8B, new byte[] {VciSupport.KEY_REF_SECURE_MESSAGING}),
                VciSupport.tlv(0x8C, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x8D, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x91, new byte[] {(byte) 0x9B}),
                VciSupport.tlv(0x8E, new byte[] {suite}),
                VciSupport.tlv(0x8F, new byte[] {ROLE_KEY_ESTABLISH}),
                VciSupport.tlv(0x90, new byte[] {ATTR_NONE})));
    expect(gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, keyDefinition)), "Define SM key 04");

    // STEP 2 - The card generates the VCI key pair; only the public point comes back.
    ResponseAPDU generated =
        expect(
            gp.transmit(
                new CommandAPDU(
                    0x00,
                    0x47,
                    0x00,
                    VciSupport.KEY_REF_SECURE_MESSAGING,
                    new byte[] {(byte) 0xAC, 0x03, (byte) 0x80, 0x01, suite},
                    256)),
            "Generate SM key on card");
    byte[] cardPublicPoint = parseGeneratedPublicPoint(generated.getData());
    System.out.println("Card SM public point: " + Hex.toHexString(cardPublicPoint).toUpperCase());

    // STEP 3 - Sign the card public key into a CVC with the VCI signer CA.
    byte[] issuerId = VciSupport.issuerIdFromPublicKey(ca.certificate.getPublicKey());
    // Subject identifier is a 16-byte GUID, matching the encoding production PIV cards use in the
    // CVC (rather than an ASCII label). A fixed value from the shared profile keeps the emulator's
    // card identity deterministic across provisioning runs.
    byte[] subjectId = StandardCardProfile.CVC_SUBJECT;
    byte[] cvcBody = VciSupport.buildCvcBody(cardPublicPoint, issuerId, subjectId);
    Signature signer = Signature.getInstance(VciSupport.cvcSignatureAlgorithm(suite));
    signer.initSign(ca.privateKey);
    signer.update(cvcBody);
    byte[] cvc = VciSupport.assembleCvc(cvcBody, signer.sign(), suite);
    if (cvc.length > 384) {
      throw new IllegalStateException("CVC exceeds the applet's 384-byte SM CVC limit: " + cvc.length);
    }
    if (!VciSupport.verifyCvc(cvc, ca.certificate.getPublicKey())) {
      throw new IllegalStateException("Freshly signed CVC failed self-verification");
    }
    System.out.println(
        "Signed CVC (" + cvc.length + " bytes): " + Hex.toHexString(cvc).toUpperCase());

    // STEP 4 - Load the CVC onto the SM key (CHANGE REFERENCE DATA, chained).
    sendChained(
        gp,
        0x24,
        suite & 0xFF,
        VciSupport.KEY_REF_SECURE_MESSAGING & 0xFF,
        VciSupport.tlv(0x30, VciSupport.tlv(0x8A, cvc)),
        "Load SM CVC");

    // STEP 4b - Install the Secure Messaging Certificate Signer (5FC122) holding the X.509 Content
    // Signing certificate whose public key verifies the SM CVC (SP 800-73-5 Part 1 Section 3.3.7,
    // Table 43: 0x70 X.509 cert, 0x71 CertInfo). A relying party reads this object to validate the
    // card CVC; making it readable lets the host trust the card's secure-messaging credential
    // without an out-of-band CA. The certificate is the VCI signer CA generated/loaded above.
    byte[] smSignerDefinition =
        VciSupport.tlv(
            0x64,
            concat(
                VciSupport.tlv(0x8B, SM_SIGNER_OBJECT_ID),
                VciSupport.tlv(0x8C, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x8D, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x91, new byte[] {(byte) 0x9B})));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, smSignerDefinition)),
        "Define Secure Messaging Certificate Signer (5FC122)");

    byte[] smSignerValue =
        concat(
            VciSupport.tlv(0x5C, SM_SIGNER_OBJECT_ID),
            VciSupport.tlv(
                0x53,
                concat(
                    VciSupport.tlv(0x70, ca.certificate.getEncoded()),
                    VciSupport.tlv(0x71, new byte[] {0x00}))));
    sendChained(
        gp, 0xDB, 0x3F, 0xFF, smSignerValue, "Write Secure Messaging Certificate Signer (5FC122)");

    // STEP 5 - Require pairing before VCI. SP 800-73-5 Part 1 Section 5.5 requires support for
    // the default VCI mode where secure messaging plus pairing-code verification establishes VCI.
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, Hex.decode("6805A203800102"))),
        "Set VCI mode to pairing-code");

    // STEP 6 - Define the pairing-code object with the SP 800-73-5 container access rules: GET
    // DATA is PIN over contact and VCI-and-PIN over contactless (Part 1 Table 2, container
    // 0x1018). A client may read and cache it over contact after PIN (Part 1 Section 5.1.3);
    // the applet's pairing VERIFY reads object content internally and is unaffected by GET DATA
    // access rules.
    byte[] pairingDefinition =
        VciSupport.tlv(
            0x64,
            concat(
                VciSupport.tlv(0x8B, PAIRING_OBJECT_ID),
                VciSupport.tlv(0x8C, new byte[] {ACCESS_PIN}),
                VciSupport.tlv(0x8D, new byte[] {(byte) (ACCESS_VCI | ACCESS_PIN)}),
                VciSupport.tlv(0x91, new byte[] {(byte) 0x9B})));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, pairingDefinition)),
        "Define pairing-code object");

    byte[] pairingPayload =
        concat(
            VciSupport.tlv(0x5C, PAIRING_OBJECT_ID),
            VciSupport.tlv(
                0x53, VciSupport.tlv(0x99, pairingCode.getBytes(StandardCharsets.US_ASCII))));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0xFF, pairingPayload)),
        "Write pairing-code object");

    // STEP 7 - Define the Discovery Object so hosts can read the VCI policy bits defined in
    // SP 800-73-5 Part 1 Section 3.3.2/Table 1.
    byte[] discoveryDefinition =
        VciSupport.tlv(
            0x64,
            concat(
                VciSupport.tlv(0x8B, new byte[] {0x7E}),
                VciSupport.tlv(0x8C, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x8D, new byte[] {ACCESS_ALWAYS}),
                VciSupport.tlv(0x91, new byte[] {(byte) 0x9B})));
    expect(
        gp.transmit(new CommandAPDU(0x00, 0xDB, 0x3F, 0x00, discoveryDefinition)),
        "Define Discovery Object");

    System.out.println(
        "VCI provisioning complete (pairing-code mode, suite 0x"
            + Integer.toHexString(suite & 0xFF)
            + ").");
  }

  // ---------------------------------------------------------------------------------------------
  // Probe (plain channel: OPACITY establishment + SM-wrapped commands)
  // ---------------------------------------------------------------------------------------------

  static boolean probe(BIBO bibo, String caCertPath, String pairingCode) throws Exception {
    requirePairingCode(pairingCode);
    EstablishedSession established = establishSecureMessaging(bibo, caCertPath);
    if (established == null) {
      return false;
    }
    VciSupport.SmSession session = established.session;

    // Pairing over the SM channel.
    VciSupport.SmResponse verifyResponse =
        verifyReferenceDataOverSm(
            bibo, session, (byte) 0x98, pairingCode.getBytes(StandardCharsets.US_ASCII));
    if (verifyResponse.statusWord != 0x9000) {
      System.out.println(
          String.format("FAIL: pairing VERIFY returned 0x%04X", verifyResponse.statusWord));
      return false;
    }
    System.out.println("Pairing code verified over secure messaging; VCI established.");

    // A wrapped GET DATA proves command decryption and response encryption both work.
    byte[] wrappedGetData =
        VciSupport.wrapCommand(
            session, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF, Hex.decode("5C017E"), true);
    VciSupport.SmResponse dataResponse =
        VciSupport.unwrapResponse(session, transceiveWithPhysicalChaining(bibo, wrappedGetData));
    if (dataResponse.statusWord != 0x9000 || dataResponse.data.length == 0) {
      System.out.println(
          String.format("FAIL: wrapped GET DATA returned 0x%04X", dataResponse.statusWord));
      return false;
    }

    for (byte[] objectId : INSPECTION_OBJECT_SWEEP) {
      VciSupport.SmResponse missingResponse = readProtectedDataObject(bibo, session, objectId);
      if (missingResponse.statusWord != 0x6A82) {
        System.out.println(
            String.format(
                "FAIL: wrapped GET DATA %s returned 0x%04X",
                Hex.toHexString(objectId).toUpperCase(), missingResponse.statusWord));
        return false;
      }
    }

    VciSupport.SmResponse signerResponse = readProtectedDataObject(bibo, session, SM_SIGNER_OBJECT_ID);
    if (signerResponse.statusWord != 0x9000 || signerResponse.data.length == 0) {
      System.out.println(
          String.format(
              "FAIL: wrapped Secure Messaging Certificate Signer returned 0x%04X",
              signerResponse.statusWord));
      return false;
    }
    System.out.println(
        "Wrapped GET DATA succeeded over VCI ("
            + dataResponse.data.length
            + " plaintext bytes). All probes passed.");
    return true;
  }

  /**
   * Result of OPACITY establishment + CVC validation without pairing. Used by probe and by tests
   * that exercise pairing/PIN negatives on an already-established SM session.
   */
  static final class EstablishedSession {
    final VciSupport.SmSession session;
    final boolean pairingRequired;
    final byte[] cvcRaw;

    EstablishedSession(VciSupport.SmSession session, boolean pairingRequired, byte[] cvcRaw) {
      this.session = session;
      this.pairingRequired = pairingRequired;
      this.cvcRaw = cvcRaw;
    }
  }

  /**
   * Establishes secure messaging using the suite advertised in the APT (CS2 or CS7) and validates
   * the card CVC against {@code caCertPath}. Does not submit the pairing code.
   *
   * @return established session, or null on failure
   */
  static EstablishedSession establishSecureMessaging(BIBO bibo, String caCertPath) throws Exception {
    ensureProvider();
    X509Certificate caCertificate = readCertificate(Paths.get(caCertPath));

    ResponseAPDU select =
        transceive(bibo, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256), "SELECT PIV");
    byte suite = detectAdvertisedSuite(select.getData());
    if (suite == 0) {
      System.out.println("FAIL: APT does not advertise CS2 or CS7 (SM key or CVC missing)");
      return null;
    }
    System.out.println(
        "APT advertises suite 0x" + Integer.toHexString(suite & 0xFF) + " secure messaging.");

    ResponseAPDU discovery =
        transceive(
            bibo,
            new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, Hex.decode("5C017E"), 256),
            "GET DATA Discovery Object");
    byte[] policyBytes = locatePinUsagePolicy(discovery.getData());
    if (policyBytes == null || (policyBytes[0] & 0x08) == 0) {
      System.out.println("FAIL: Discovery Object does not advertise VCI");
      return null;
    }
    boolean pairingRequired = (policyBytes[0] & 0x04) == 0;
    System.out.println("Discovery Object: VCI advertised, pairing required = " + pairingRequired);

    int field = VciSupport.coordLength(suite);
    int nLen = field / 2;
    X9ECParameters curve = VciSupport.curveForSuite(suite);
    ECDomainParameters domain =
        new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    SecureRandom random = new SecureRandom();
    BigInteger d;
    do {
      d = new BigInteger(curve.getN().bitLength(), random);
    } while (d.signum() <= 0 || d.compareTo(curve.getN()) >= 0);
    ECPoint hostPoint = curve.getG().multiply(d).normalize();
    byte[] hostPublicPoint = VciSupport.encodePoint(hostPoint);
    byte[] idH = new byte[8];

    byte[] witness = concat(new byte[] {0x00}, VciSupport.buildWitness(hostPublicPoint));
    byte[] template =
        VciSupport.tlv(
            0x7C, concat(VciSupport.tlv(0x81, witness), VciSupport.tlv(0x82, new byte[0])));
    // Use raw transport: CS7 CVC responses often continue with GET RESPONSE (61 XX).
    byte[] gaFirst =
        bibo.transceive(
            new CommandAPDU(
                    0x00, 0x87, suite, VciSupport.KEY_REF_SECURE_MESSAGING, template, 256)
                .getBytes());
    byte[] gaData = reassembleGaResponse(bibo, new ResponseAPDU(gaFirst));

    int[] outer = VciSupport.locateTlv(gaData, 0, 0x7C);
    if (outer == null) {
      System.out.println("FAIL: establishment response missing 7C template");
      return null;
    }
    int[] challenge = VciSupport.locateTlv(gaData, outer[1], 0x82);
    // cb(1) + N + authCryptogram(16) + at least 1 byte of CVC
    if (challenge == null || challenge[2] < 1 + nLen + 16 + 1) {
      System.out.println("FAIL: establishment response missing 82 challenge");
      return null;
    }
    int valueOffset = challenge[1];
    byte cbIcc = gaData[valueOffset];
    byte[] nIcc = Arrays.copyOfRange(gaData, valueOffset + 1, valueOffset + 1 + nLen);
    byte[] cryptogram =
        Arrays.copyOfRange(gaData, valueOffset + 1 + nLen, valueOffset + 1 + nLen + 16);
    byte[] cvcRaw =
        Arrays.copyOfRange(gaData, valueOffset + 1 + nLen + 16, valueOffset + challenge[2]);
    System.out.println("Card CVC received (" + cvcRaw.length + " bytes).");

    if (!VciSupport.verifyCvc(cvcRaw, caCertificate.getPublicKey())) {
      System.out.println("FAIL: card CVC signature did not verify against the signer CA");
      return null;
    }
    System.out.println("Card CVC verified against signer CA.");

    byte[] cardPublicPoint = VciSupport.extractCardPublicPoint(cvcRaw);
    ECPoint cardPoint = curve.getCurve().decodePoint(cardPublicPoint);
    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
    agreement.init(new ECPrivateKeyParameters(d, domain));
    BigInteger z = agreement.calculateAgreement(new ECPublicKeyParameters(cardPoint, domain));
    byte[] sharedSecret = toFixedLength(z, field);

    byte[] idSicc = VciSupport.computeIdSicc(cvcRaw);
    VciSupport.SessionKeys sessionKeys =
        VciSupport.deriveSessionKeys(suite, sharedSecret, idH, hostPublicPoint, idSicc, nIcc);

    byte[] expectedCryptogram =
        VciSupport.computeAuthCryptogram(sessionKeys.skCfrm, idSicc, idH, hostPublicPoint);
    if (!Arrays.equals(Arrays.copyOf(expectedCryptogram, 16), cryptogram)) {
      System.out.println("FAIL: card authentication cryptogram mismatch (cbIcc=" + cbIcc + ")");
      return null;
    }
    System.out.println("Authentication cryptogram verified; SM session keys derived.");
    return new EstablishedSession(new VciSupport.SmSession(sessionKeys), pairingRequired, cvcRaw);
  }

  /** Returns ALG_CS2, ALG_CS7, or 0 if neither is advertised in the APT. */
  private static byte detectAdvertisedSuite(byte[] apt) {
    if (containsSequence(apt, new byte[] {(byte) 0x80, 0x01, VciSupport.ALG_CS7})) {
      return VciSupport.ALG_CS7;
    }
    if (containsSequence(apt, new byte[] {(byte) 0x80, 0x01, VciSupport.ALG_CS2})) {
      return VciSupport.ALG_CS2;
    }
    return 0;
  }

  /** Reassembles a GA response that may span GET RESPONSE (61 XX). */
  private static byte[] reassembleGaResponse(BIBO bibo, ResponseAPDU first) {
    ByteArrayOutputStream logical = new ByteArrayOutputStream();
    byte[] response = first.getBytes();
    while (true) {
      if (response.length < 2) {
        throw new IllegalStateException("Card returned a malformed GA response");
      }
      int sw =
          ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
      logical.write(response, 0, response.length - 2);
      if ((sw & 0xFF00) != 0x6100) {
        return logical.toByteArray();
      }
      int le = sw & 0xFF;
      if (le == 0) {
        le = 256;
      }
      response = bibo.transceive(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00, (byte) le});
    }
  }

  /**
   * Submits VERIFY for the given key reference over the established SM session (pairing code 0x98,
   * PIV PIN 0x80, Global PIN 0x00, etc.).
   */
  static VciSupport.SmResponse verifyReferenceDataOverSm(
      BIBO bibo, VciSupport.SmSession session, byte keyRef, byte[] referenceData) throws Exception {
    byte[] wrapped =
        VciSupport.wrapCommand(session, (byte) 0x20, (byte) 0x00, keyRef, referenceData, false);
    return VciSupport.unwrapResponse(session, transceiveWithPhysicalChaining(bibo, wrapped));
  }

  /** Wrapped GET DATA of the Discovery Object over the SM session. */
  static VciSupport.SmResponse getDiscoveryOverSm(BIBO bibo, VciSupport.SmSession session)
      throws Exception {
    byte[] wrapped =
        VciSupport.wrapCommand(
            session, (byte) 0xCB, (byte) 0x3F, (byte) 0xFF, Hex.decode("5C017E"), true);
    return VciSupport.unwrapResponse(session, transceiveWithPhysicalChaining(bibo, wrapped));
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private static void requirePairingCode(String pairingCode) {
    if (pairingCode == null || !pairingCode.matches("[0-9]{8}")) {
      throw new IllegalArgumentException("Pairing code must be exactly 8 ASCII digits");
    }
  }

  private static VciSupport.SmResponse readProtectedDataObject(
      BIBO bibo, VciSupport.SmSession session, byte[] objectId) {
    byte[] wrappedGetData =
        VciSupport.wrapCommand(
            session,
            (byte) 0xCB,
            (byte) 0x3F,
            (byte) 0xFF,
            VciSupport.tlv(0x5C, objectId),
            true);
    return VciSupport.unwrapResponse(session, transceiveWithPhysicalChaining(bibo, wrappedGetData));
  }

  private static byte[] transceiveWithPhysicalChaining(BIBO bibo, byte[] command) {
    ByteArrayOutputStream logical = new ByteArrayOutputStream();
    byte[] response = bibo.transceive(command);
    while (true) {
      if (response.length < 2) {
        throw new IllegalStateException("Card returned a malformed response APDU");
      }

      int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
      logical.write(response, 0, response.length - 2);
      if ((sw & 0xFF00) != 0x6100) {
        logical.write((sw >> 8) & 0xFF);
        logical.write(sw & 0xFF);
        return logical.toByteArray();
      }

      int le = sw & 0xFF;
      response = bibo.transceive(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00, (byte) le});
    }
  }

  private static byte[] parseGeneratedPublicPoint(byte[] response) {
    int[] template = VciSupport.locateTlv(response, 0, 0x7F49);
    if (template == null) {
      throw new IllegalStateException("GENERATE response missing 7F49 template");
    }
    int[] point = VciSupport.locateTlv(response, template[1], 0x86);
    // CS2: 65-byte point; CS7: 97-byte point.
    if (point == null || (point[2] != 65 && point[2] != 97)) {
      throw new IllegalStateException(
          "GENERATE response missing 65- or 97-byte 86 public point (got "
              + (point == null ? "null" : point[2])
              + ")");
    }
    return Arrays.copyOfRange(response, point[1], point[1] + point[2]);
  }

  private static void sendChained(
      GPSession gp, int ins, int p1, int p2, byte[] payload, String context) {
    int offset = 0;
    while (offset < payload.length) {
      int chunkLength = Math.min(MAX_CHUNK, payload.length - offset);
      byte[] chunk = Arrays.copyOfRange(payload, offset, offset + chunkLength);
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

  private static ResponseAPDU transceive(BIBO bibo, CommandAPDU command, String context) {
    ResponseAPDU response = new ResponseAPDU(bibo.transceive(command.getBytes()));
    if (response.getSW() != 0x9000) {
      throw new IllegalStateException(
          String.format("%s failed with SW 0x%04X", context, response.getSW()));
    }
    return response;
  }

  /** Finds the 2-byte PIN usage policy value following a {@code 5F 2F 02} tag in the response. */
  private static byte[] locatePinUsagePolicy(byte[] discovery) {
    for (int i = 0; i + 4 < discovery.length; i++) {
      if (discovery[i] == (byte) 0x5F && discovery[i + 1] == (byte) 0x2F && discovery[i + 2] == 2) {
        return new byte[] {discovery[i + 3], discovery[i + 4]};
      }
    }
    return null;
  }

  private static boolean containsSequence(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }

  private static byte[] toFixedLength(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    if (raw.length == length) {
      return raw;
    }
    byte[] out = new byte[length];
    if (raw.length > length) {
      System.arraycopy(raw, raw.length - length, out, 0, length);
    } else {
      System.arraycopy(raw, 0, out, length - raw.length, raw.length);
    }
    return out;
  }

  private static byte[] concat(byte[]... arrays) {
    int total = 0;
    for (byte[] array : arrays) {
      total += array.length;
    }
    byte[] out = new byte[total];
    int offset = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, out, offset, array.length);
      offset += array.length;
    }
    return out;
  }

  private static void writePem(Path path, Object object) throws Exception {
    try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.US_ASCII);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(object);
    }
  }

  static X509Certificate readCertificate(Path path) throws Exception {
    ensureProvider();
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
        PEMParser parser = new PEMParser(reader)) {
      Object object = parser.readObject();
      if (!(object instanceof X509CertificateHolder)) {
        throw new IllegalArgumentException("Expected an X.509 certificate PEM in " + path);
      }
      return new JcaX509CertificateConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCertificate((X509CertificateHolder) object);
    }
  }

  static PrivateKey readPrivateKey(Path path) throws Exception {
    ensureProvider();
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
        PEMParser parser = new PEMParser(reader)) {
      Object object = parser.readObject();
      JcaPEMKeyConverter converter =
          new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
      if (object instanceof PEMKeyPair) {
        return converter.getKeyPair((PEMKeyPair) object).getPrivate();
      }
      if (object instanceof PrivateKeyInfo) {
        return converter.getPrivateKey((PrivateKeyInfo) object);
      }
      throw new IllegalArgumentException("Unsupported private key PEM object in " + path);
    }
  }
}
