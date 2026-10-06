/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.attestation.AttestationProofService;
import dev.mistial.tools.openfips201.common.ApduSupport;
import dev.mistial.tools.openfips201.common.BerTlvReader;
import dev.mistial.tools.openfips201.common.BerTlvWriter;
import dev.mistial.tools.openfips201.common.CardSession;
import dev.mistial.tools.openfips201.common.CardTransport;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.LogicalResponseCollector;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardIdentityService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import java.util.Arrays;

/** {@link PivIssuanceClient} over one card transport. */
public final class ApduPivIssuanceClient implements PivIssuanceClient {
  /** F9 key definition: ATTR_NONE (non-importable), P-256, role SIGN, admin and access never. */
  static final byte[] F9_DEFINITION = HexUtil.parse("66128B01F98C01008D01008E01118F0104900100");

  static final byte[] GENERATE_P256 = HexUtil.parse("AC03800111");
  private static final byte[] GET_VERSION = HexUtil.parse("5C032F4756");
  private static final byte[] GET_STATUS = HexUtil.parse("5C032F4753");
  /** ISO/IEC 7816-4 Table 7 '6A89' (file already exists): the key reference is already defined. */
  private static final int SW_OBJECT_EXISTS = 0x6A89;

  /** A chunk of at most 0xEF octets fits a short APDU after SCP03 wrapping. */
  private static final int MAX_FRAME = 0xEF;

  private final CardTransport transport;
  private final ScpConfig stockScp;
  private final AppletInstallRequest install;
  private final byte[] pivAid;
  private final byte proofSlot;
  private final byte[] proofPin;

  /**
   * @param install the applet to install; its instance AID is the PIV application addressed later
   * @param proofPin eight-octet PIV wire-format PIN set for the proof-key attestation
   */
  public ApduPivIssuanceClient(
      CardTransport transport,
      ScpConfig stockScp,
      AppletInstallRequest install,
      byte proofSlot,
      byte[] proofPin) {
    this.transport = transport;
    this.stockScp = stockScp;
    this.install = install;
    this.pivAid = HexUtil.parse(install.instanceAid);
    this.proofSlot = proofSlot;
    this.proofPin = proofPin.clone();
  }

  @Override
  public CardIdentity readIdentity() {
    // Reading the KDD selects the ISD, so GET CPLC that follows is answered by the ISD rather than
    // by whichever application was selected before.
    byte[] kdd = new CardDiversificationDataService().readKdd(transport).kdd;
    CardIdentityService.Result cplc = new CardIdentityService().read(transport);
    return new CardIdentity(cplc.cplc, cplc.cplcFields, kdd);
  }

  @Override
  public void installApplet() throws Exception {
    try (GlobalPlatformSession isd =
        transport.openGlobalPlatformSession(GlobalPlatformSession.ISD_AID, stockScp)) {
      new AppletInstallService().install(isd, install);
    }
  }

  @Override
  public byte[] generateF9() throws Exception {
    try (GlobalPlatformSession piv = transport.openGlobalPlatformSession(pivAid, stockScp)) {
      ResponseAPDU defined = piv.transmit(new CommandAPDU(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION));
      if (defined.getSW() != 0x9000 && defined.getSW() != SW_OBJECT_EXISTS) {
        throw new SamApduException("define F9", defined.getSW());
      }
      byte[] generated =
          collect(
              piv,
              piv.transmit(new CommandAPDU(0x84, 0x47, 0x00, 0xF9, GENERATE_P256, 256)),
              "generate F9");
      return publicPoint(generated);
    }
  }

  @Override
  public byte[] proveF9(byte[] nonce) throws Exception {
    try (GlobalPlatformSession piv = transport.openGlobalPlatformSession(pivAid, stockScp)) {
      return collect(
          piv, piv.transmit(new CommandAPDU(0x84, 0xF9, 0xF9, 0x01, nonce, 256)), "F9 PROVE");
    }
  }

  @Override
  public void loadF9Certificate(byte[] certificate) throws Exception {
    byte[] payload = BerTlvWriter.encode(0x30, BerTlvWriter.encode(0x70, certificate));
    try (GlobalPlatformSession piv = transport.openGlobalPlatformSession(pivAid, stockScp)) {
      int offset = 0;
      while (offset < payload.length) {
        int length = Math.min(MAX_FRAME, payload.length - offset);
        boolean last = offset + length == payload.length;
        ResponseAPDU response =
            piv.transmit(
                new CommandAPDU(
                    last ? 0x84 : 0x94,
                    0x24,
                    0x11,
                    0xF9,
                    Arrays.copyOfRange(payload, offset, offset + length)));
        if (response.getSW() != 0x9000) {
          throw new SamApduException("load F9 certificate", response.getSW());
        }
        offset += length;
      }
    }
  }

  @Override
  public byte[] readF9Certificate() {
    BIBO bibo = transport.bibo();
    ApduSupport.selectApplication(bibo, pivAid, "SELECT PIV");
    return LogicalResponseCollector.collect(
        borrowed(bibo),
        bibo.transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 256)),
        0x00,
        4096,
        "read F9 certificate");
  }

  @Override
  public ProofResult attestProofKey() throws Exception {
    AttestationProofService proofs = new AttestationProofService();
    byte[] point;
    try (GlobalPlatformSession piv = transport.openGlobalPlatformSession(pivAid, stockScp)) {
      proofs.setProofPin(piv, proofPin);
      point = proofs.createAndGenerateProofKey(piv, proofSlot);
    }
    byte[] leaf;
    try {
      leaf = proofs.collectPlainProof(transport, pivAid, proofSlot, proofPin);
    } catch (Exception e) {
      try (GlobalPlatformSession cleanup = transport.openGlobalPlatformSession(pivAid, stockScp)) {
        proofs.deleteCreatedProofKey(cleanup, proofSlot);
      } catch (Exception cleanupFailure) {
        e.addSuppressed(cleanupFailure);
      }
      throw e;
    }
    boolean deleted;
    try (GlobalPlatformSession cleanup = transport.openGlobalPlatformSession(pivAid, stockScp)) {
      deleted = proofs.deleteCreatedProofKey(cleanup, proofSlot);
      // Card stock never ships with a known PIN: the proof PIN is replaced by eight random digits
      // that are not recorded; personalization sets the cardholder PIN over the secure channel.
      byte[] unknown = randomPin();
      try {
        proofs.setProofPin(cleanup, unknown);
      } finally {
        Arrays.fill(unknown, (byte) 0);
      }
    }
    return new ProofResult(leaf, point, deleted);
  }

  /** Eight uniformly random ASCII digits in the PIV PIN wire format. */
  static byte[] randomPin() {
    java.security.SecureRandom random = new java.security.SecureRandom();
    byte[] pin = new byte[8];
    for (int i = 0; i < pin.length; i++) {
      pin[i] = (byte) ('0' + random.nextInt(10));
    }
    return pin;
  }

  @Override
  public byte[] getVersion() {
    return plainGetData(GET_VERSION, "GET VERSION");
  }

  @Override
  public byte[] getStatus() {
    return plainGetData(GET_STATUS, "GET STATUS");
  }

  @Override
  public void rotateKeys(DerivedScpKeys keys) throws Exception {
    new CardKeyRotationService().rotate(transport, stockScp, keys, false);
  }

  @Override
  public boolean pivInstancePresent() {
    int sw =
        transport.bibo().transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, pivAid, 256)).getSW();
    return sw == 0x9000 || (sw & 0xFF00) == 0x6100;
  }

  @Override
  public void deleteInstance(ScpConfig keys) throws Exception {
    try (GlobalPlatformSession isd =
        transport.openGlobalPlatformSession(
            GlobalPlatformSession.ISD_AID, keys == null ? stockScp : keys)) {
      if (install.loadCap) {
        isd.gp().deleteAID(new pro.javacard.capfile.AID(HexUtil.parse(install.packageAid)), true);
      } else {
        isd.gp().deleteAID(new pro.javacard.capfile.AID(pivAid), false);
      }
    }
  }

  @Override
  public void restoreStockKeys(ScpConfig current, int version) throws Exception {
    ScpConfig stock =
        new ScpConfig(stockScp.mode, version, stockScp.encKey, stockScp.macKey, stockScp.dekKey);
    new CardKeyRotationService()
        .rotate(transport, current, DerivedScpKeys.fromConfig(stock), false);
  }

  private byte[] plainGetData(byte[] request, String label) {
    BIBO bibo = transport.bibo();
    ApduSupport.selectApplication(bibo, pivAid, "SELECT PIV");
    return LogicalResponseCollector.collect(
        borrowed(bibo),
        bibo.transmit(new CommandAPDU(0x80, 0xCB, 0xFF, 0xFF, request, 256)),
        0x00,
        1024,
        label);
  }

  /** A session view of {@code bibo}; the enclosing transport owns the connection. */
  private static CardSession borrowed(final BIBO bibo) {
    return new CardSession() {
      @Override
      public ResponseAPDU transmit(CommandAPDU command) {
        return bibo.transmit(command);
      }

      @Override
      public void close() {}
    };
  }

  private static byte[] collect(CardSession session, ResponseAPDU response, String label) {
    if (response.getSW1() != 0x61 && response.getSW() != 0x9000) {
      throw new SamApduException(label, response.getSW());
    }
    return LogicalResponseCollector.collect(session, response, 0x84, 4096, label);
  }

  /** Extracts the point from {@code 7F49 L 86 41 <point>}. */
  static byte[] publicPoint(byte[] generated) {
    BerTlvReader.Tlv template = BerTlvReader.read(generated, 0);
    if (template.tag != 0x7F49 || template.nextOffset != generated.length) {
      throw new IllegalStateException("F9 generation returned no public-key template");
    }
    BerTlvReader.Tlv point =
        BerTlvReader.read(generated, template.valueOffset, template.nextOffset);
    if (point.tag != 0x86
        || point.length != IssuanceCrypto.POINT_LENGTH
        || point.nextOffset != template.nextOffset) {
      throw new IllegalStateException("F9 generation returned no P-256 point");
    }
    return Arrays.copyOfRange(generated, point.valueOffset, point.nextOffset);
  }
}
