/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

/**
 * The issuer SAM command set. Every method sends exactly the APDU it names and fails with {@link
 * SamApduException} on any status word other than 9000; nothing is retried.
 *
 * <p>Personalization, VERIFY PIN, BEGIN ISSUANCE and ISSUE require the GlobalPlatform secure
 * channel on which the implementation sends its commands; BEGIN ISSUANCE and ISSUE also require a
 * verified operator PIN.
 */
public interface SamClient {
  /** VOID reason: recorded by an operator without a more specific reason. */
  int VOID_UNSPECIFIED = 0x00;

  /** VOID reason: the card carrying the OPID is reissued with the next OPID. */
  int VOID_REISSUE = 0x01;

  /** GET DATA STATUS (P1=00 P2=01). */
  SamStatus status();

  /**
   * GET DATA STATUS signed over {@code nonce} (P1=01 P2=01); returns {@code statusTLV || 9E sig}.
   */
  byte[] signedStatus(byte[] nonce);

  /**
   * PUT PARAMETERS (D0) with the IssuerSamParameters v5 DER: the LCG and the FF1 key wrapped to the
   * SAM transport key, in one command.
   */
  void putParameters(byte[] parametersDer);

  /** SET OPERATOR PIN (D2 P2=81). */
  void setOperatorPin(byte[] pin);

  /** GENERATE SAM KEY (46); returns the 65-octet SAM public point. */
  byte[] generateKey();

  /** LOAD SAM CERTIFICATE (D4); returns the SAM SKI the SAM reports. */
  byte[] loadCertificate(byte[] certificate);

  /** LOCK (D6); returns {@code 71 genesis 72 sig}. */
  byte[] lock();

  /** VERIFY PIN (20 P2=81). */
  void verifyPin(byte[] pin);

  /** BEGIN ISSUANCE (84); returns the 32-octet nonce. */
  byte[] beginIssuance();

  /** ISSUE F9 (2A P2=F9) {@code 86 F9pub | 9E PoP | 93 Validity}; returns the raw response. */
  byte[] issue(byte[] f9Point, byte[] proofOfPossession, byte[] validityDer);

  /** TOP UP (32) {@code 80 ts | 81 add | 9E rootSig}; returns {@code 71 entry 72 sig}. */
  byte[] topUp(long timestamp, long add, byte[] rootSignature);

  /** GET DATA SAM CERTIFICATE (P2=02). */
  byte[] samCertificate();

  /** GET DATA LAST ENTRY (P2=03); returns {@code 71 entry 72 sig}. */
  byte[] lastEntry();

  /**
   * GET DATA PARAMS (P2=04, secure channel): {@code 81 format | 82 IIN | 83 batch | 84 k | 85
   * issued | 86 quota | 93 paramsDigest}. The LCG parameters themselves are never returned.
   */
  byte[] parameters();

  /**
   * DECIPHER (2C) {@code 80 11 <17 ASCII digits>}, secure channel and operator PIN: reverses an
   * OPID of this SAM's IIN to its batch and, for the SAM's own batch, its issuance index.
   */
  DecipherResult decipher(String opid);

  /**
   * TERMINATE (E6), secure channel and operator PIN: commits the final TERM entry, returns it
   * signed ({@code 71 entry 72 sig}) and clears the SAM key. Irreversible.
   */
  byte[] terminate();

  /** GENERATE TRANSPORT KEY (4A), secure channel: the one-time P-256 transport point. */
  byte[] generateTransportKey();

  /** CHANGE OPERATOR PIN (24 P2=81) {@code 80 L old | 81 L new}, secure channel. */
  void changeOperatorPin(byte[] oldPin, byte[] newPin);

  /**
   * VOID (2E) {@code 80 04 seq | 81 01 reason}, secure channel and operator PIN; returns {@code 71
   * entry 72 sig}.
   */
  byte[] voidIssuance(long seq, int reason);

  /** CLOSE (E8), secure channel and operator PIN; returns {@code 71 entry 72 sig}. */
  byte[] close();
}
