/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.opid.Opid;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/** Offline verification of OpenPhysical attestation chains. */
@Command(
    name = "attestation",
    mixinStandardHelpOptions = true,
    description = "Verify OpenPhysical attestation certificate chains.",
    subcommands = AttestationCommand.Verify.class)
public final class AttestationCommand implements Callable<Integer> {
  /** Exit status for a chain that passed every check. */
  public static final int EXIT_VALID = 0;

  /** Exit status for a chain with at least one failed check. */
  public static final int EXIT_INVALID = 1;

  /** Exit status for unusable arguments or unreadable input files. */
  public static final int EXIT_USAGE = 2;

  @Spec CommandSpec spec;

  @Override
  public Integer call() {
    spec.commandLine().usage(spec.commandLine().getErr());
    return EXIT_USAGE;
  }

  /**
   * {@code attestation verify}: runs {@link AttestationVerifier} over PEM files, or over the leaf
   * and F9 certificate read from a card ({@code --from-card}, {@link CardAttestationReader}).
   *
   * <p>Inputs are collected into a {@link VerificationRequest} by {@link #request()}. The anchor
   * and SAM certificate come from files or from a producer's {@code root.pem} and a batch's {@code
   * sam.pem}.
   */
  @Command(
      name = "verify",
      mixinStandardHelpOptions = true,
      description = {
        "Verify root -> SAM -> F9 -> leaf offline.",
        "Exit status: 0 valid, 1 invalid, 2 usage or input error."
      })
  public static final class Verify implements Callable<Integer> {
    @Spec CommandSpec spec;

    @Option(
        names = "--anchor",
        paramLabel = "ROOT.pem",
        description =
            "Trust anchor (root) certificate, one PEM CERTIFICATE block. Default with --producer:"
                + " the producer's root.pem.")
    Path anchor;

    @Option(
        names = "--from-card",
        description =
            "Read the leaf (00 F9 <slot> 00) and the F9 certificate (00 F9 F9 00) from the card.")
    boolean fromCard;

    @Option(names = "--target", description = "With --from-card: pcsc:<reader> or zmq:<endpoint>.")
    String target;

    @Option(names = "--slot", description = "With --from-card: key reference in hex, e.g. 9A.")
    String slot;

    @Option(
        names = "--pin-env",
        description = "With --from-card: environment variable with the PIV PIN.")
    String pinEnv;

    @Option(names = "--pin-file", description = "With --from-card: owner-only PIV PIN file.")
    String pinFile;

    @Option(
        names = "--producer",
        description = "Take the anchor and (with --batch) the SAM certificate from this producer.")
    String producer;

    @Option(names = "--batch", description = "With --producer: the batch whose SAM certified F9.")
    String batch;

    @Option(
        names = "--chain",
        paramLabel = "CERT.pem",
        description =
            "Intermediate certificate, repeatable, in issuing order: the SAM certificate, then the"
                + " F9 certificate.")
    List<Path> chain = new ArrayList<Path>();

    @Option(
        names = "--leaf",
        paramLabel = "LEAF.pem",
        description = "PIV attestation leaf certificate (required unless --from-card).")
    Path leaf;

    @Option(
        names = "--slot-cert",
        paramLabel = "CERT.pem",
        description = "Certificate stored in the attested slot; its SPKI must equal the leaf SPKI.")
    Path slotCertificate;

    @Option(
        names = "--expect-opid",
        paramLabel = "OPID",
        description = "OPID the F9 certificate must carry.")
    String expectOpid;

    @Option(
        names = "--at",
        paramLabel = "ISO8601",
        description =
            "Evaluation time, e.g. 2026-01-31T12:00:00Z or 2026-01-31 (UTC midnight). Default:"
                + " now.")
    String at;

    @Option(
        names = "--registry",
        paramLabel = "allocations.jsonl",
        description =
            "Root allocation registry (from the root station's export-trust): the SAM's"
                + " allocation must be bound to it.")
    Path registry;

    @Option(
        names = "--voids",
        paramLabel = "voids.json",
        description =
            "SAM-signed VOID entries (from the production station's export-trust): the F9 OPID"
                + " must not be voided.")
    Path voids;

    @Option(names = "--json", description = "Print the report as JSON.")
    boolean json;

    @Override
    public Integer call() {
      PrintWriter out = spec.commandLine().getOut();
      PrintWriter err = spec.commandLine().getErr();
      VerificationRequest request;
      try {
        request = request();
      } catch (Exception e) {
        err.println("Error: " + e.getMessage());
        err.flush();
        return EXIT_USAGE;
      }
      VerificationReport report = AttestationVerifier.verify(request);
      out.print(json ? report.toJson() + System.lineSeparator() : report.toTable());
      out.flush();
      return report.valid() ? EXIT_VALID : EXIT_INVALID;
    }

    /**
     * Builds the request from the options; DER validity is left to the verifier. With {@code
     * --from-card} the leaf and F9 certificate come from the card and {@code --chain} carries only
     * the SAM certificate, unless {@code --producer --batch} supplies it.
     */
    VerificationRequest request() throws Exception {
      int chainLimit = fromCard ? 1 : 2;
      if (chain.size() > chainLimit) {
        throw new IllegalArgumentException(
            fromCard
                ? "with --from-card, --chain accepts only the SAM certificate"
                : "--chain accepts at most two certificates (SAM, then F9), got " + chain.size());
      }
      if (batch != null && producer == null) {
        throw new IllegalArgumentException("--batch requires --producer");
      }
      byte[] anchorDer;
      if (anchor != null) {
        anchorDer = StrictDer.readSinglePemBlock(anchor);
      } else if (producer != null) {
        anchorDer =
            StrictDer.readSinglePemBlock(
                dev.mistial.tools.openfips201.producer.ProducerPaths.producer(producer)
                    .resolve("root.pem"));
      } else {
        throw new IllegalArgumentException("--anchor (or --producer) is required");
      }
      VerificationRequest.Builder builder = VerificationRequest.builder().anchor(anchorDer);
      if (batch != null) {
        if (!chain.isEmpty()) {
          throw new IllegalArgumentException("use either --chain or --producer --batch");
        }
        builder.samCertificate(
            dev.mistial.tools.openfips201.issuance.IssuanceService.samCertificate(
                dev.mistial.tools.openfips201.producer.BatchMetadata.read(producer, batch)));
      } else if (chain.size() >= 1) {
        builder.samCertificate(StrictDer.readSinglePemBlock(chain.get(0)));
      }
      if (fromCard) {
        if (leaf != null) {
          throw new IllegalArgumentException("--leaf and --from-card are exclusive");
        }
        if (target == null || slot == null) {
          throw new IllegalArgumentException("--from-card requires --target and --slot");
        }
        CardAttestationReader.Result card =
            CardAttestationReader.read(
                dev.mistial.tools.openfips201.common.CardTarget.parse(target),
                parseSlot(slot),
                pin());
        builder.leaf(card.leaf()).f9Certificate(card.f9Certificate());
      } else {
        if (leaf == null) {
          throw new IllegalArgumentException("--leaf (or --from-card) is required");
        }
        builder.leaf(StrictDer.readSinglePemBlock(leaf));
        if (chain.size() == 2) {
          builder.f9Certificate(StrictDer.readSinglePemBlock(chain.get(1)));
        }
      }
      if (slotCertificate != null) {
        builder.slotCertificate(StrictDer.readSinglePemBlock(slotCertificate));
      }
      if (expectOpid != null) {
        builder.expectOpid(Opid.parse(expectOpid));
      }
      if (at != null) {
        builder.at(parseTime(at));
      }
      if (registry != null) {
        String content =
            new String(
                java.nio.file.Files.readAllBytes(registry),
                java.nio.charset.StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<String>();
        for (String line : content.split("\n")) {
          if (!line.isEmpty()) {
            lines.add(line);
          }
        }
        builder.registry(lines);
      }
      if (voids != null) {
        builder.voids(readVoids(voids));
      }
      return builder.build();
    }

    /** The VOID entries of a {@code openfips201.voids/1} file. */
    static List<VerificationRequest.SignedVoid> readVoids(Path file) throws IOException {
      com.google.gson.JsonObject document =
          com.google.gson.JsonParser.parseString(
                  new String(
                      java.nio.file.Files.readAllBytes(file),
                      java.nio.charset.StandardCharsets.UTF_8))
              .getAsJsonObject();
      if (!document.has("schema")
          || !dev.mistial.tools.openfips201.producer.TrustExportService.VOIDS_SCHEMA.equals(
              document.get("schema").getAsString())) {
        throw new IllegalArgumentException(file + " is not a voids.json file");
      }
      List<VerificationRequest.SignedVoid> out = new ArrayList<VerificationRequest.SignedVoid>();
      for (com.google.gson.JsonElement element : document.getAsJsonArray("voids")) {
        com.google.gson.JsonObject entry = element.getAsJsonObject();
        out.add(
            new VerificationRequest.SignedVoid(
                dev.mistial.tools.openfips201.common.HexUtil.parse(
                    entry.get("entry").getAsString()),
                dev.mistial.tools.openfips201.common.HexUtil.parse(
                    entry.get("sig").getAsString())));
      }
      return out;
    }

    /** The PIV PIN in the eight-octet wire format (ASCII digits padded with FF), or null. */
    private byte[] pin() throws IOException {
      char[] chars =
          dev.mistial.tools.openfips201.crypto.SecretSource.of("--pin", null, pinEnv, pinFile)
              .chars();
      if (chars == null) {
        return null;
      }
      try {
        if (chars.length < 6 || chars.length > 8) {
          throw new IllegalArgumentException("the PIV PIN must be 6 to 8 characters");
        }
        byte[] pin = new byte[8];
        java.util.Arrays.fill(pin, (byte) 0xFF);
        for (int i = 0; i < chars.length; i++) {
          pin[i] = (byte) chars[i];
        }
        return pin;
      } finally {
        java.util.Arrays.fill(chars, '\0');
      }
    }
  }

  /** A PIV key reference in hex ({@code 9A}, {@code 82}). */
  static byte parseSlot(String value) {
    try {
      int parsed = Integer.parseInt(value, 16);
      if (parsed < 0 || parsed > 0xFF) {
        throw new NumberFormatException();
      }
      return (byte) parsed;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("--slot must be a one-byte hex key reference: " + value);
    }
  }

  /**
   * Parses an ISO 8601 instant ({@code 2026-01-31T12:00:00Z}), offset date-time ({@code
   * 2026-01-31T12:00:00+01:00}) or calendar date ({@code 2026-01-31}, taken as 00:00 UTC).
   */
  static Date parseTime(String value) {
    try {
      return Date.from(Instant.parse(value));
    } catch (DateTimeParseException ignored) {
      // Not an instant with a Z designator; try the other accepted forms.
    }
    try {
      return Date.from(OffsetDateTime.parse(value).toInstant());
    } catch (DateTimeParseException ignored) {
      // Not an offset date-time; try a calendar date.
    }
    try {
      return Date.from(LocalDate.parse(value).atStartOfDay(ZoneOffset.UTC).toInstant());
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException("--at is not an ISO 8601 time: " + value, e);
    }
  }
}
