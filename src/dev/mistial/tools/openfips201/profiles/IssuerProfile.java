/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.profiles;

import dev.mistial.tools.openfips201.pkcs11.Pkcs11Config;

public final class IssuerProfile {
  public String name;
  public Scp stockScp = new Scp();
  public Applet applet = new Applet();
  public Attestation attestation = new Attestation();
  public CardKeys cardKeys = new CardKeys();
  public Pkcs11Config pkcs11 = new Pkcs11Config();
  public Receipts receipts = new Receipts();

  public static final class Scp {
    public String mode = "scp03";
    public int keyVersion = 0;
    public String masterKeyEnv;
  }

  public static final class Applet {
    public String capPath = "build/bin/OpenFIPS201-OP-0.1.cap";
    public String packageAid = "A00000030800001000";
    public String appletAid = "A000000308000010000100";
    public String instanceAid = "A000000308000010000100";
    public boolean loadCap = true;
    public boolean deleteExisting = false;
  }

  public static final class Attestation {
    public String issuerSigner = "pkcs11";
    public String issuerSubject = "CN=OpenFIPS201 Cardstock";
    public int issuerValidityDays = 3650;
    public String proofSlot = "82";
    public boolean deleteProofKey = true;
    public String issuerObjectId = "5FFF01";
  }

  public static final class CardKeys {
    public String deriver = "profile-hmac";
    public String kdf = "hmac-sha256-counter-v1";
    public int newKeyVersion = 1;
    public String masterKeyEnv;
    public String export = "none";
    public String wrappingCertificate;
  }

  public static final class Receipts {
    public String directory = "receipts";
  }
}
