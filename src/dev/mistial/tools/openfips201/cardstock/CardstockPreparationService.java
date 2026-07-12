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
import dev.mistial.tools.openfips201.gp.CardKeyDerivationService;
import dev.mistial.tools.openfips201.gp.CardKeyRotationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
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

  public Path prepare(CardTarget target, IssuerProfile profile, SigningKey signer, boolean yes)
      throws Exception {
    if (!yes && !"emulator-dev".equals(profile.name)) {
      throw new IllegalArgumentException("cardstock prepare requires --yes for physical issuer profiles");
    }

    ScpConfig stockScp = stockScp(profile);
    CardstockReceipt receipt = new CardstockReceipt();
    receipt.profileName = profile.name;
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
    try (GlobalPlatformSession piv =
        GlobalPlatformSession.open(target, HexUtil.parse(profile.applet.instanceAid), stockScp)) {
      authority =
          new AttestationAuthorityService()
              .importGeneratedAuthority(
                  piv,
                  signer,
                  profile.attestation.issuerSubject,
                  profile.attestation.issuerValidityDays,
                  HexUtil.parse(profile.attestation.issuerObjectId));
      receipt.operationsPerformed.add("F9 authority imported");
      proof =
          new AttestationProofService()
              .prove(
                  piv,
                  (byte) Integer.parseInt(profile.attestation.proofSlot, 16),
                  profile.attestation.deleteProofKey);
      receipt.operationsPerformed.add("attestation proof collected");
    }

    DerivedScpKeys derived =
        new CardKeyDerivationService()
            .derive(cardMaster(profile), deriveContext(profile, receipt), profile.cardKeys.newKeyVersion);
    receipt.newScpMode = "SCP03";
    receipt.newScpKeyVersion = profile.cardKeys.newKeyVersion;
    receipt.newScpEncKcv = derived.encKcv;
    receipt.newScpMacKcv = derived.macKcv;
    receipt.newScpDekKcv = derived.dekKcv;
    receipt.hsmDeriver = profile.cardKeys.deriver;

    new CardKeyRotationService().rotate(target, stockScp, derived);
    receipt.operationsPerformed.add("SCP keys rotated and verified");

    receipt.f9IssuerCertificateSha256 =
        HexUtil.format(MessageDigest.getInstance("SHA-256").digest(authority.issuerCertificate.getEncoded()));
    receipt.f9ProofSlot = profile.attestation.proofSlot;
    receipt.f9ProofCertificateBase64 = Base64.getEncoder().encodeToString(proof.certificate);
    receipt.proofKeyDeleted = proof.proofKeyDeleted;
    if (profile.attestation.deleteProofKey && !proof.proofKeyDeleted) {
      receipt.warnings.add("proof key deletion was requested but the card returned 6985");
    }

    Path directory = Paths.get(profile.receipts.directory);
    Files.createDirectories(directory);
    Path output = directory.resolve(profile.name + "-" + System.currentTimeMillis() + ".json");
    Files.write(output, GSON.toJson(receipt).getBytes(StandardCharsets.UTF_8));
    return output;
  }

  private static ScpConfig stockScp(IssuerProfile profile) {
    if ("emulator-dev".equals(profile.name) && profile.stockScp.masterKeyEnv == null) {
      return ScpConfig.defaultTestScp03();
    }
    return ScpConfig.fromMaster(
        ScpConfig.parseMode(profile.stockScp.mode),
        profile.stockScp.keyVersion,
        secret(profile.stockScp.masterKeyEnv));
  }

  private static byte[] cardMaster(IssuerProfile profile) {
    String env = profile.cardKeys.masterKeyEnv;
    if ("emulator-dev".equals(profile.name) && (env == null || System.getenv(env) == null)) {
      return HexUtil.parse("00112233445566778899AABBCCDDEEFF");
    }
    return secret(env);
  }

  private static byte[] secret(String env) {
    if (env == null || env.isEmpty()) {
      throw new IllegalArgumentException("profile must name an environment variable for secret material");
    }
    String value = System.getenv(env);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + env);
    }
    return HexUtil.parse(value);
  }

  private static String deriveContext(IssuerProfile profile, CardstockReceipt receipt) {
    return profile.name + "|" + receipt.timestamp + "|" + receipt.target;
  }
}
