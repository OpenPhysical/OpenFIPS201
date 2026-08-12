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
  public String batchName;
  public String timestamp;
  public String target;
  public String cplc;
  public java.util.Map<String, String> cplcFields;
  public String capPath;
  public String packageAid;
  public String appletAid;
  public String newScpMode;
  public int newScpKeyVersion;
  public String newScpKdf;
  public String cardKdd;
  public String newScpEncKcv;
  public String newScpMacKcv;
  public String newScpDekKcv;
  public String hsmSigner;
  public String hsmDeriver;
  public String rootSubject;
  /** Durable F9 instance id (32 uppercase hex). */
  public String instanceId;

  public String f9Subject;
  public String f9CertificateSerialHex;
  public String f9SpkiSha256;
  public String f9IssuerCertificateSha256;
  /** Base64 DER of the F9 issuer certificate. */
  public String f9CertificateBase64;

  public String f9ProofSlot;
  public String f9ProofCertificateBase64;
  public boolean f9ProofIssuerMatched;
  public boolean proofKeyDeleted;
  public final List<String> operationsPerformed = new ArrayList<String>();
}
