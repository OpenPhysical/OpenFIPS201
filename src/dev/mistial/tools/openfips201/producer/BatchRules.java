/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import dev.mistial.tools.openfips201.attestation.F9SubjectNames;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.gp.ScpKeyChecks;
import dev.mistial.tools.openfips201.opid.Opid;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import org.bouncycastle.asn1.x500.X500Name;

/** Size limits, subjects, stock keys and the receipts CSV of a batch. */
public final class BatchRules {
  /** Applet limit on the F9 subject DER (PIVAttestation and the SAM's issued certificate). */
  public static final int F9_SUBJECT_MAX = 128;

  /** SAM limit on the F9 subject template RDN content. */
  public static final int F9_TEMPLATE_CONTENT_MAX = 96;

  /** SAM limit on its own certificate subject DER. */
  public static final int SAM_SUBJECT_MAX = 128;

  /** Hex length of the SAM identifier (its 10-octet KDD) appended as serialNumber. */
  static final int SAM_ID_HEX_LENGTH = 20;

  public static final int DEFAULT_F9_VALIDITY_DAYS = 3650;
  public static final int DEFAULT_SAM_VALIDITY_DAYS = 3650;

  public static final String CSV_HEADER =
      "timestamp,producer,batch,target,status,stage,opid,issuance_seq,cplc,kdd_initial,"
          + "kdd_final,new_key_version,enc_kcv,mac_kcv,dek_kcv,f9_ski,f9_cert_sha256,guid,fascn,"
          + "receipt\n";

  private BatchRules() {}

  /** {@code IIII-NNNN}: the name of the batch of (iin, batch). */
  public static String batchName(int iin, int batch) {
    return String.format(Locale.ROOT, "%04d-%04d", iin, batch);
  }

  /** The F9 subject with an OPID (always 17 digits) must fit the applet and SAM limits. */
  public static void requireF9SubjectFits(String template, int iin) {
    X500Name name = new X500Name(template);
    int content = der(name).length - headerLength(der(name));
    if (content > F9_TEMPLATE_CONTENT_MAX) {
      throw new IllegalArgumentException(
          "F9 subject template is "
              + content
              + " octets of RDNs; the SAM accepts at most "
              + F9_TEMPLATE_CONTENT_MAX);
    }
    byte[] worst = der(F9SubjectNames.withOpid(name, Opid.of(iin, Opid.E_MODULUS - 1)));
    if (worst.length > F9_SUBJECT_MAX) {
      throw new IllegalArgumentException(
          "F9 subject with an OPID is "
              + worst.length
              + " octets; the card accepts at most "
              + F9_SUBJECT_MAX);
    }
  }

  public static void requireSamSubjectFits(String template) {
    X500Name subject = samSubject(template, repeat('F', SAM_ID_HEX_LENGTH));
    if (der(subject).length > SAM_SUBJECT_MAX) {
      throw new IllegalArgumentException(
          "SAM subject is " + der(subject).length + " octets; the SAM accepts " + SAM_SUBJECT_MAX);
    }
  }

  /** {@code template} with a final {@code serialNumber=<samId>} RDN. */
  public static X500Name samSubject(String template, String samId) {
    X500Name base = new X500Name(template);
    org.bouncycastle.asn1.x500.RDN[] rdns =
        Arrays.copyOf(base.getRDNs(), base.getRDNs().length + 1);
    rdns[rdns.length - 1] =
        new org.bouncycastle.asn1.x500.RDN(
            F9SubjectNames.SERIAL_NUMBER,
            new org.bouncycastle.asn1.DERPrintableString(samId.toUpperCase(Locale.ROOT), true));
    return new X500Name(rdns);
  }

  /**
   * A fresh stock SCP03 key for the batch's cards, recorded only by its GP Section B.6 KCV. It is
   * written to the new owner-only file {@code out} when given; otherwise its hex is returned for
   * display. The caller never stores it.
   *
   * @return the hex key, or null when written to {@code out}
   */
  public static String newStockKey(BatchMetadata metadata, Path out) throws IOException {
    byte[] stockKey = new byte[16];
    new SecureRandom().nextBytes(stockKey);
    try {
      metadata.stockScp.mode = "scp03";
      metadata.stockScp.keyVersion = 1;
      metadata.stockScp.kcv = ScpKeyChecks.kcvAes(stockKey);
      metadata.stockScp.kcvAlgorithm = ScpKeyChecks.KCV_ALGORITHM_GP_B6_AES;
      if (out == null) {
        return HexUtil.format(stockKey);
      }
      char[] hex = HexUtil.format(stockKey).toCharArray();
      byte[] content = new byte[hex.length + 1];
      for (int i = 0; i < hex.length; i++) {
        content[i] = (byte) hex[i];
      }
      content[hex.length] = '\n';
      try {
        SecureFiles.writeNew(out, content);
      } finally {
        Arrays.fill(content, (byte) 0);
        Arrays.fill(hex, '\0');
      }
      return null;
    } finally {
      Arrays.fill(stockKey, (byte) 0);
    }
  }

  /**
   * Refuses a stock key whose GP Section B.6 KCV differs from {@code batch.json}, before any card
   * I/O.
   */
  public static void requireStockKcv(BatchMetadata metadata, byte[] stockScpKey) {
    if (stockScpKey == null || stockScpKey.length == 0) {
      throw new IllegalArgumentException("Stock SCP03 master key is required");
    }
    if (!ScpKeyChecks.KCV_ALGORITHM_GP_B6_AES.equals(metadata.stockScp.kcvAlgorithm)) {
      throw new IllegalArgumentException(
          "batch.json kcvAlgorithm is not supported: " + metadata.stockScp.kcvAlgorithm);
    }
    String actual = ScpKeyChecks.kcvAes(stockScpKey);
    if (!actual.equalsIgnoreCase(metadata.stockScp.kcv)) {
      throw new IllegalArgumentException(
          "Stock SCP03 key KCV "
              + actual
              + " does not match batch "
              + metadata.name
              + " KCV "
              + metadata.stockScp.kcv
              + "; refusing before any card I/O");
    }
  }

  public static void ensureCsvHeader(Path csv) throws IOException {
    if (Files.exists(csv)) {
      return;
    }
    SecureFiles.writeNew(csv, CSV_HEADER.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] der(X500Name name) {
    try {
      return name.getEncoded("DER");
    } catch (IOException e) {
      throw new IllegalArgumentException("subject cannot be encoded", e);
    }
  }

  private static int headerLength(byte[] der) {
    int first = der[1] & 0xFF;
    return first < 0x80 ? 2 : 2 + (first & 0x7F);
  }

  private static String repeat(char value, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, value);
    return new String(chars);
  }
}
