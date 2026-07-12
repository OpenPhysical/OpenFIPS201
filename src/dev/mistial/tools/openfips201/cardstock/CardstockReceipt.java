/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.cardstock;

import java.util.ArrayList;
import java.util.List;

public final class CardstockReceipt {
  public String profileName;
  public String timestamp;
  public String target;
  public String capPath;
  public String packageAid;
  public String appletAid;
  public String newScpMode;
  public int newScpKeyVersion;
  public String newScpEncKcv;
  public String newScpMacKcv;
  public String newScpDekKcv;
  public String hsmSigner;
  public String hsmDeriver;
  public String f9IssuerCertificateSha256;
  public String f9ProofSlot;
  public String f9ProofCertificateBase64;
  public boolean proofKeyDeleted;
  public final List<String> operationsPerformed = new ArrayList<String>();
  public final List<String> warnings = new ArrayList<String>();
}
