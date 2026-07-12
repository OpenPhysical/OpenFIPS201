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
import dev.mistial.tools.openfips201.gp.CardDiversificationDataService;
import dev.mistial.tools.openfips201.gp.CardIdentityService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.gp.Scp03Kdf3DerivationService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;
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
    if (!yes && !"emulator-dev".equals(profile.name)) {
      throw new IllegalArgumentException("cardstock prepare requires --yes for physical issuer profiles");
    }

    ScpConfig stockScp = stockScpOverride == null ? stockScp(profile) : stockScpOverride;
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
      proof =
          new AttestationProofService()
              .prove(
                  piv,
                  (byte) Integer.parseInt(profile.attestation.proofSlot, 16),
                  profile.attestation.deleteProofKey);
      if (profile.attestation.deleteProofKey && !proof.proofKeyDeleted) {
        throw new IllegalStateException("proof key deletion failed");
      }
      receipt.operationsPerformed.add("attestation proof collected");
    }

    CardIdentityService.Result identity = new CardIdentityService().read(target);
    receipt.cplc = identity.cplc;
    receipt.cplcFields = identity.cplcFields;

    CardDiversificationDataService.Result kdd = new CardDiversificationDataService().readKdd(target);
    receipt.cardKdd = HexUtil.format(kdd.kdd);
    DerivedScpKeys derived = deriveCardKeys(profile, receipt, kdd.kdd);
    receipt.newScpMode = "SCP03";
    receipt.newScpKeyVersion = profile.cardKeys.newKeyVersion;
    receipt.newScpKdf = "emulator-dev-local".equals(receipt.hsmDeriver)
        ? "hmac-sha256-counter-v1"
        : profile.cardKeys.kdf;
    receipt.newScpEncKcv = derived.encKcv;
    receipt.newScpMacKcv = derived.macKcv;
    receipt.newScpDekKcv = derived.dekKcv;

    new CardKeyRotationService().rotate(target, stockScp, derived);
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

  private static ScpConfig stockScp(IssuerProfile profile) {
    if ("emulator-dev".equals(profile.name) && profile.stockScp.masterKeyEnv == null) {
      return ScpConfig.defaultTestScp03();
    }
    return ScpConfig.fromMaster(
        ScpConfig.parseMode(profile.stockScp.mode),
        profile.stockScp.keyVersion,
        secret(profile.stockScp.masterKeyEnv));
  }

  private static DerivedScpKeys deriveCardKeys(
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
    if (!"pkcs11".equals(profile.cardKeys.deriver)
        || !"scp03-kdf3".equals(profile.cardKeys.kdf)) {
      throw new IllegalArgumentException("cardKeys must use deriver=pkcs11 and kdf=scp03-kdf3");
    }
    Pkcs11Config master = cardMasterKey(profile);
    receipt.hsmDeriver = "pkcs11:" + describeKey(master);
    return new Scp03Kdf3DerivationService().derive(master, kdd, profile.cardKeys.newKeyVersion);
  }

  private static Pkcs11Config cardMasterKey(IssuerProfile profile) {
    Pkcs11Config base =
        profile.cardKeys.pkcs11 == null ? profile.pkcs11.copy() : merge(profile.pkcs11, profile.cardKeys.pkcs11);
    if (profile.cardKeys.masterKeyAlias != null) {
      base.keyAlias = profile.cardKeys.masterKeyAlias;
    }
    if (profile.cardKeys.masterKeyId != null) {
      base.keyId = profile.cardKeys.masterKeyId;
    }
    if ((base.keyAlias == null || base.keyAlias.isEmpty()) && (base.keyId == null || base.keyId.isEmpty())) {
      throw new IllegalArgumentException("cardKeys must set masterKeyAlias or masterKeyId");
    }
    return base;
  }

  private static Pkcs11Config merge(Pkcs11Config defaults, Pkcs11Config override) {
    Pkcs11Config result = defaults.copy();
    if (override.module != null) {
      result.module = override.module;
    }
    if (override.tokenLabel != null) {
      result.tokenLabel = override.tokenLabel;
    }
    if (override.slot != null) {
      result.slot = override.slot;
    }
    if (override.keyAlias != null) {
      result.keyAlias = override.keyAlias;
    }
    if (override.keyId != null) {
      result.keyId = override.keyId;
    }
    if (override.pinEnv != null) {
      result.pinEnv = override.pinEnv;
    }
    if (override.pinFile != null) {
      result.pinFile = override.pinFile;
    }
    if (override.softhsmConfig != null) {
      result.softhsmConfig = override.softhsmConfig;
    }
    return result;
  }

  private static String describeKey(Pkcs11Config config) {
    if (config.keyAlias != null && !config.keyAlias.isEmpty()) {
      return config.keyAlias;
    }
    return "id:" + config.keyId;
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
