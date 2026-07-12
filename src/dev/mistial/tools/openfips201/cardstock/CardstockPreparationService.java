/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.cardstock;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.applet.AppletInstallRequest;
import dev.mistial.tools.openfips201.applet.AppletInstallService;
import dev.mistial.tools.openfips201.attestation.AttestationAuthorityService;
import dev.mistial.tools.openfips201.attestation.AttestationProofService;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.GlobalPlatformSession;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.gp.CardKeyPreflightService;
import dev.mistial.tools.openfips201.gp.CardKeyDerivationService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardIdentityService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.gp.IssuerCardKeyService;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

public final class CardstockPreparationService {
  private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
  private final IssuerCardKeyService issuerCardKeys = new IssuerCardKeyService();

  public Path prepare(CardTarget target, IssuerProfile profile, SigningKey signer, boolean yes)
      throws Exception {
    return prepare(target, profile, signer, yes, null, null);
  }

  public Path prepare(
      CardTarget target,
      IssuerProfile profile,
      SigningKey signer,
      boolean yes,
      String batchName,
      Path receiptDirectory)
      throws Exception {
    return prepare(target, profile, signer, yes, batchName, receiptDirectory, null);
  }

  public Path prepare(
      CardTarget target,
      IssuerProfile profile,
      SigningKey signer,
      boolean yes,
      String batchName,
      Path receiptDirectory,
      ScpConfig stockScpOverride)
      throws Exception {
    return prepare(target, profile, signer, yes, batchName, receiptDirectory, stockScpOverride, null, null);
  }

  public Path prepare(
      CardTarget target,
      IssuerProfile profile,
      SigningKey signer,
      boolean yes,
      String batchName,
      Path receiptDirectory,
      ScpConfig stockScpOverride,
      String profilePath,
      String stockScpKey)
      throws Exception {
    if (!yes && !"emulator-dev".equals(profile.name)) {
      throw new IllegalArgumentException("cardstock prepare requires --yes for physical issuer profiles");
    }

    ScpConfig stockScp = stockScpOverride == null ? issuerCardKeys.stockScp(profile) : stockScpOverride;
    byte[] preflightKdd = null;
    if (!target.isZmq()) {
      CardKeyPreflightService.Request preflightRequest = new CardKeyPreflightService.Request();
      preflightRequest.target = target;
      preflightRequest.current = stockScp;
      preflightRequest.profile = profile;
      preflightRequest.profilePath = profilePath;
      preflightRequest.stockScpKey = stockScpKey;
      CardKeyPreflightService.Result preflight =
          new CardKeyPreflightService().preflight(preflightRequest);
      preflightKdd = preflight.kdd;
      writePreflight(preflightDirectory(profile, receiptDirectory), profile.name, preflight);
    }
    CardstockReceipt receipt = new CardstockReceipt();
    receipt.profileName = profile.name;
    receipt.batchName = batchName;
    receipt.timestamp = Instant.now().toString();
    receipt.target = target.displayName();
    receipt.capPath = profile.applet.capPath;
    receipt.packageAid = profile.applet.packageAid;
    receipt.appletAid = profile.applet.appletAid;
    receipt.hsmSigner = signer.description();

    try (GlobalPlatformSession isd =
        GlobalPlatformSession.open(target, GlobalPlatformSession.ISD_AID, stockScp)) {
      AppletInstallRequest install = new AppletInstallRequest();
      install.capPath = Paths.get(profile.applet.capPath);
      install.packageAid = profile.applet.packageAid;
      install.appletAid = profile.applet.appletAid;
      install.instanceAid = profile.applet.instanceAid;
      install.loadCap = profile.applet.loadCap;
      install.deleteExisting = profile.applet.deleteExisting;
      new AppletInstallService().install(isd, install);
      receipt.operationsPerformed.add("applet installed");
    }

    AttestationProofService.Result proof;
    AttestationAuthorityService.Result authority;
    byte proofSlot = (byte) Integer.parseInt(profile.attestation.proofSlot, 16);
    boolean proofKeyCreated = false;
    try (GlobalPlatformSession piv =
        GlobalPlatformSession.open(target, HexUtil.parse(profile.applet.instanceAid), stockScp)) {
      authority =
          new AttestationAuthorityService()
              .importGeneratedAuthority(
                  piv,
                  signer,
                  profile.attestation.rootSubject == null
                      ? profile.attestation.issuerSubject
                      : profile.attestation.rootSubject,
                  profile.attestation.issuerSubject,
                  profile.attestation.issuerValidityDays,
                  HexUtil.parse(profile.attestation.issuerObjectId));
      receipt.operationsPerformed.add("F9 authority imported");
      new AttestationProofService().createAndGenerateProofKey(piv, proofSlot);
      proofKeyCreated = true;
    }

    try {
      byte[] proofCertificate =
          new AttestationProofService()
              .collectPlainProof(target, HexUtil.parse(profile.applet.instanceAid), proofSlot);
      boolean proofKeyDeleted = false;
      if (profile.attestation.deleteProofKey) {
        try (GlobalPlatformSession cleanup =
            GlobalPlatformSession.open(target, HexUtil.parse(profile.applet.instanceAid), stockScp)) {
          proofKeyDeleted = new AttestationProofService().deleteCreatedProofKey(cleanup, proofSlot);
        }
      }
      proof = new AttestationProofService.Result(proofCertificate, proofKeyDeleted);
      receipt.operationsPerformed.add("attestation proof collected");
    } catch (Exception e) {
      if (profile.attestation.deleteProofKey && proofKeyCreated) {
        try (GlobalPlatformSession cleanup =
            GlobalPlatformSession.open(target, HexUtil.parse(profile.applet.instanceAid), stockScp)) {
          new AttestationProofService().deleteCreatedProofKey(cleanup, proofSlot);
        } catch (Exception cleanupFailure) {
          e.addSuppressed(cleanupFailure);
        }
      }
      throw e;
    }

    CardIdentityService.Result identity = new CardIdentityService().read(target);
    receipt.cplc = identity.cplc;
    receipt.cplcFields = identity.cplcFields;

    byte[] kddBytes =
        preflightKdd == null ? new CardDiversificationDataService().readKdd(target).kdd : preflightKdd;
    receipt.cardKdd = HexUtil.format(kddBytes);
    DerivedScpKeys derived = deriveCardKeys(profile, receipt, kddBytes);
    receipt.newScpMode = "SCP03";
    receipt.newScpKeyVersion = profile.cardKeys.newKeyVersion;
    receipt.newScpKdf = "emulator-dev-local".equals(receipt.hsmDeriver)
        ? "hmac-sha256-counter-v1"
        : profile.cardKeys.kdf;
    receipt.newScpEncKcv = derived.encKcv;
    receipt.newScpMacKcv = derived.macKcv;
    receipt.newScpDekKcv = derived.dekKcv;

    new CardKeyRotationService().rotate(target, stockScp, derived, profile.cardKeys.replaceExisting);
    receipt.operationsPerformed.add("SCP keys rotated and verified");

    receipt.f9IssuerCertificateSha256 =
        HexUtil.format(MessageDigest.getInstance("SHA-256").digest(authority.issuerCertificate.getEncoded()));
    receipt.rootSubject = authority.issuerCertificate.getIssuerX500Principal().getName();
    receipt.f9Subject = authority.issuerCertificate.getSubjectX500Principal().getName();
    receipt.f9ProofSlot = profile.attestation.proofSlot;
    receipt.f9ProofCertificateBase64 = Base64.getEncoder().encodeToString(proof.certificate);
    receipt.proofKeyDeleted = proof.proofKeyDeleted;

    Path directory =
        receiptDirectory == null ? Paths.get(profile.receipts.directory) : receiptDirectory;
    Files.createDirectories(directory);
    Path output = directory.resolve(profile.name + "-" + System.currentTimeMillis() + ".json");
    Files.write(output, GSON.toJson(receipt).getBytes(StandardCharsets.UTF_8));
    return output;
  }

  private static Path preflightDirectory(IssuerProfile profile, Path receiptDirectory) {
    return receiptDirectory == null ? Paths.get(profile.receipts.directory) : receiptDirectory;
  }

  private static void writePreflight(
      Path directory, String profileName, CardKeyPreflightService.Result preflight) throws Exception {
    Files.createDirectories(directory);
    Path output = directory.resolve(profileName + "-preflight-" + System.currentTimeMillis() + ".json");
    Files.write(output, GSON.toJson(preflight).getBytes(StandardCharsets.UTF_8));
  }

  private DerivedScpKeys deriveCardKeys(
      IssuerProfile profile, CardstockReceipt receipt, byte[] kdd) throws Exception {
    if ("emulator-dev".equals(profile.name)
        && (profile.cardKeys.masterKeyEnv == null
            || System.getenv(profile.cardKeys.masterKeyEnv) == null)) {
      receipt.hsmDeriver = "emulator-dev-local";
      return new CardKeyDerivationService()
          .derive(
              HexUtil.parse("00112233445566778899AABBCCDDEEFF"),
              deriveContext(profile, receipt),
              profile.cardKeys.newKeyVersion);
    }
    receipt.hsmDeriver = "pkcs11:" + issuerCardKeys.describeCardMasterKey(profile);
    return issuerCardKeys.deriveCardKeys(profile, kdd);
  }

  private static String deriveContext(IssuerProfile profile, CardstockReceipt receipt) {
    return profile.name + "|" + receipt.timestamp + "|" + receipt.target;
  }
}
