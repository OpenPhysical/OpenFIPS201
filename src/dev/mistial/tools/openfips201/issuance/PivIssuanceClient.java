/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import java.util.Map;

/**
 * The card side of the per-card issuance sequence. Administrative commands run over the batch stock
 * secure channel; reads that a relying party would perform run over plain PIV.
 */
public interface PivIssuanceClient {
  /** CPLC and the 10-octet KDD from INITIALIZE UPDATE. */
  CardIdentity readIdentity() throws Exception;

  /** Installs the PIV applet over the stock secure channel. */
  void installApplet() throws Exception;

  /**
   * Defines F9 as a non-importable P-256 signing key and generates it on the card ({@code 84 47 00
   * F9 05 AC03800111}); returns the 65-octet public point.
   */
  byte[] generateF9() throws Exception;

  /** {@code 84 F9 F9 01 <N>}: the card's signature over {@code "OPF9POP" || N || F9pub}. */
  byte[] proveF9(byte[] nonce) throws Exception;

  /** {@code 84 24 11 F9 30 82 LLLL 70 82 LLLL <cert>}, chained; the card activates F9. */
  void loadF9Certificate(byte[] certificate) throws Exception;

  /** {@code 00 F9 F9 00} over plain PIV: the stored F9 certificate. */
  byte[] readF9Certificate() throws Exception;

  /**
   * Generates a temporary proof key, collects its attestation leaf over plain PIV, and deletes the
   * key. The proof key is deleted even when collection fails. Afterwards the local PIN is set to a
   * random value that is not recorded, so the card never ships with the proof PIN.
   */
  ProofResult attestProofKey() throws Exception;

  /** GET VERSION ({@code 80 CB FF FF 5C 03 2F 47 56}) response data. */
  byte[] getVersion() throws Exception;

  /** GET STATUS ({@code 80 CB FF FF 5C 03 2F 47 53}) response data. */
  byte[] getStatus() throws Exception;

  /** Rotates the card's ISD keys from the stock keys to {@code keys} and verifies them. */
  void rotateKeys(DerivedScpKeys keys) throws Exception;

  /** Whether the card answers SELECT for the PIV instance (no keys needed). */
  boolean pivInstancePresent() throws Exception;

  /**
   * Deletes the PIV instance (and the package when the CAP is loaded by this client) over a channel
   * opened with {@code keys}: the card's derived keys after a rotation, or the stock keys when
   * {@code keys} is null.
   */
  void deleteInstance(ScpConfig keys) throws Exception;

  /** Rotates the card's ISD keys from {@code current} back to the stock keys at {@code version}. */
  void restoreStockKeys(ScpConfig current, int version) throws Exception;

  /** CPLC and KDD read from the card. */
  final class CardIdentity {
    public final String cplc;
    public final Map<String, String> cplcFields;
    private final byte[] kdd;

    public CardIdentity(String cplc, Map<String, String> cplcFields, byte[] kdd) {
      this.cplc = cplc;
      this.cplcFields = cplcFields;
      this.kdd = kdd.clone();
    }

    public byte[] kdd() {
      return kdd.clone();
    }
  }

  /** The attestation leaf of the temporary proof key. */
  final class ProofResult {
    private final byte[] leaf;
    private final byte[] point;
    public final boolean deleted;

    public ProofResult(byte[] leaf, byte[] point, boolean deleted) {
      this.leaf = leaf.clone();
      this.point = point.clone();
      this.deleted = deleted;
    }

    public byte[] leaf() {
      return leaf.clone();
    }

    public byte[] point() {
      return point.clone();
    }
  }
}
