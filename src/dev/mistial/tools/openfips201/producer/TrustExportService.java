/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.producer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.mistial.tools.openfips201.attestation.StrictDer;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * {@code producer export-trust}: the public material a relying party needs to verify the producer's
 * cards, and {@code trust.json} ({@code openfips201.trust/2}) describing it.
 *
 * <ul>
 *   <li>root station: {@code root.pem}, one {@code sam-<batch>.pem} per bound SAM, and the
 *       allocation registry {@code allocations.jsonl};
 *   <li>production station: {@code root.pem}, the SAM certificate of every received batch, and
 *       {@code voids.json} ({@code openfips201.voids/1}): every SAM-signed VOID entry of its
 *       ledgers.
 * </ul>
 *
 * <p>Nothing secret is read or written: no key, PIN, LCG or FF1 material. Existing files in the
 * output directory are never overwritten.
 */
public final class TrustExportService {
  public static final String SCHEMA = "openfips201.trust/2";
  public static final String VOIDS_SCHEMA = "openfips201.voids/1";
  private static final Gson GSON =
      new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

  /** {@code trust.json}. */
  public static final class Manifest {
    public String schema = SCHEMA;
    public String producer;
    public String station;
    public Root root = new Root();
    public final List<Sam> sams = new ArrayList<Sam>();

    /** Root station: {@code allocations.jsonl}. */
    public String registry;

    /** Production station: {@code voids.json} and its entry count. */
    public String voids;

    public int voidCount;
  }

  /** {@code voids.json}. */
  public static final class Voids {
    public String schema = VOIDS_SCHEMA;
    public String producer;
    public final List<VoidEntry> voids = new ArrayList<VoidEntry>();
  }

  /** One SAM-signed VOID entry. */
  public static final class VoidEntry {
    public String batch;
    public String samSki;
    public long seq;
    public String opid;
    public int reason;
    public String entry;
    public String sig;
  }

  public static final class Root {
    public String file;
    public String sha256;
    public String ski;
    public String subject;
  }

  public static final class Sam {
    public String file;
    public String batch;
    public int iin;
    public String samId;
    public String sha256;
    public String ski;
    public String notBefore;
    public String notAfter;
  }

  public Manifest export(String producer, Path out) throws Exception {
    Path producerDirectory = ProducerPaths.producer(producer);
    if (!Files.exists(ProducerPaths.producerProfile(producer))) {
      throw new IllegalArgumentException("Producer is not set up: " + producer);
    }
    X509Certificate root =
        StrictDer.readSinglePemCertificate(producerDirectory.resolve("root.pem"));
    Manifest manifest = new Manifest();
    manifest.producer = producer;
    manifest.root.file = "root.pem";
    manifest.root.sha256 = sha256(root);
    manifest.root.ski = HexUtil.format(KeyIdentifiers.ski(root.getPublicKey()));
    manifest.root.subject = root.getSubjectX500Principal().getName();

    Map<String, byte[]> files = new LinkedHashMap<String, byte[]>();
    files.put("root.pem", pem(root));
    manifest.station = StationGuard.station(producer);
    if (ProducerSetupService.STATION_ROOT.equals(manifest.station)) {
      exportRoot(producer, manifest, files);
    } else {
      exportProduction(producer, manifest, files);
    }
    files.put("trust.json", GSON.toJson(manifest).getBytes(StandardCharsets.UTF_8));

    Files.createDirectories(out);
    for (String name : files.keySet()) {
      if (Files.exists(out.resolve(name), LinkOption.NOFOLLOW_LINKS)) {
        throw new IllegalArgumentException(out.resolve(name) + " already exists");
      }
    }
    for (Map.Entry<String, byte[]> file : files.entrySet()) {
      SecureFiles.writeNew(out.resolve(file.getKey()), file.getValue());
    }
    return manifest;
  }

  private static void exportRoot(String producer, Manifest manifest, Map<String, byte[]> files)
      throws Exception {
    Path registry = dev.mistial.tools.openfips201.issuance.AllocationRegistry.file(producer);
    if (Files.isRegularFile(registry, LinkOption.NOFOLLOW_LINKS)) {
      manifest.registry = "allocations.jsonl";
      files.put(manifest.registry, Files.readAllBytes(registry));
    }
    Path directory = ProducerPaths.producer(producer).resolve("root").resolve("batches");
    if (!Files.isDirectory(directory)) {
      return;
    }
    TreeMap<String, Path> records = new TreeMap<String, Path>();
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory, "*.sam.json")) {
      for (Path entry : entries) {
        records.put(entry.getFileName().toString(), entry);
      }
    }
    for (Path entry : records.values()) {
      dev.mistial.tools.openfips201.issuance.RootBatchRecord.SamFile record =
          new Gson()
              .fromJson(
                  new String(Files.readAllBytes(entry), StandardCharsets.UTF_8),
                  dev.mistial.tools.openfips201.issuance.RootBatchRecord.SamFile.class);
      X509Certificate sam =
          StrictDer.parseCertificate(java.util.Base64.getDecoder().decode(record.certificate));
      if (!sha256(sam).equals(record.certificateSha256)) {
        throw new IllegalStateException(entry + " records a different certificate hash");
      }
      String name = BatchRules.batchName(record.iin, record.batch);
      files.put("sam-" + name + ".pem", pem(sam));
      manifest.sams.add(samRecord(name, record.iin, record.samId, sam));
    }
  }

  private static void exportProduction(
      String producer, Manifest manifest, Map<String, byte[]> files) throws Exception {
    Voids voids = new Voids();
    voids.producer = producer;
    Map<String, BatchMetadata> batches = new TreeMap<String, BatchMetadata>();
    Path batchRoot = ProducerPaths.producer(producer).resolve("batches");
    if (Files.isDirectory(batchRoot)) {
      try (DirectoryStream<Path> entries = Files.newDirectoryStream(batchRoot)) {
        for (Path entry : entries) {
          if (Files.isRegularFile(entry.resolve("batch.json"), LinkOption.NOFOLLOW_LINKS)) {
            BatchMetadata batch = BatchMetadata.read(producer, entry.getFileName().toString());
            if (batch.sam != null && batch.sam.certificate != null) {
              batches.put(batch.name, batch);
            }
          }
        }
      }
    }
    for (BatchMetadata batch : batches.values()) {
      X509Certificate sam =
          StrictDer.readSinglePemCertificate(batch.directory().resolve(batch.sam.certificate));
      if (!sha256(sam).equals(batch.sam.certificateSha256)) {
        throw new IllegalStateException(
            "sam.pem of batch " + batch.name + " differs from its batch.json record");
      }
      Sam record = samRecord(batch.name, batch.opid.iin, batch.sam.samId, sam);
      manifest.sams.add(record);
      files.put(record.file, pem(sam));
      dev.mistial.tools.openfips201.issuance.IssuanceLedger ledger =
          new dev.mistial.tools.openfips201.issuance.IssuanceLedger(
              batch.directory().resolve(batch.ledger));
      for (dev.mistial.tools.openfips201.issuance.IssuanceLedger.Line line : ledger.read()) {
        if (!dev.mistial.tools.openfips201.issuance.IssuanceLedger.VOID.equals(line.type())) {
          continue;
        }
        VoidEntry entry = new VoidEntry();
        entry.batch = batch.name;
        entry.samSki = record.ski;
        entry.seq = line.number("seq");
        entry.opid = line.string("opid");
        entry.reason = (int) line.number("reason");
        entry.entry = line.string("entry");
        entry.sig = line.string("sig");
        voids.voids.add(entry);
      }
    }
    manifest.voids = "voids.json";
    manifest.voidCount = voids.voids.size();
    files.put(manifest.voids, GSON.toJson(voids).getBytes(StandardCharsets.UTF_8));
  }

  private static Sam samRecord(String batch, int iin, String samId, X509Certificate sam)
      throws Exception {
    Sam record = new Sam();
    record.file = "sam-" + batch + ".pem";
    record.batch = batch;
    record.iin = iin;
    record.samId = samId;
    record.sha256 = sha256(sam);
    record.ski = HexUtil.format(KeyIdentifiers.ski(sam.getPublicKey()));
    record.notBefore = sam.getNotBefore().toInstant().toString();
    record.notAfter = sam.getNotAfter().toInstant().toString();
    return record;
  }

  private static String sha256(X509Certificate certificate) throws Exception {
    return HexUtil.format(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
  }

  private static byte[] pem(X509Certificate certificate) throws IOException {
    StringWriter text = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
      writer.writeObject(certificate);
    }
    return text.toString().getBytes(StandardCharsets.US_ASCII);
  }
}
