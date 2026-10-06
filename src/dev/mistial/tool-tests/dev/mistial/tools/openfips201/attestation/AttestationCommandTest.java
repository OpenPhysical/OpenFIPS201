/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.attestation.AttestationTestChains.Chain;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class AttestationCommandTest {
  private static final String AT = "2026-06-01T00:00:00Z";

  @TempDir Path dir;

  private Chain chain;
  private Path root;
  private Path sam;
  private Path f9;
  private Path leaf;
  private StringWriter out;

  @BeforeEach
  void writeChain() throws Exception {
    chain = AttestationTestChains.build();
    root = write("root.pem", AttestationTestChains.pem(chain.root));
    sam = write("sam.pem", AttestationTestChains.pem(chain.sam));
    f9 = write("f9.pem", AttestationTestChains.pem(chain.f9));
    leaf = write("leaf.pem", AttestationTestChains.pem(chain.leaf));
  }

  @Test
  void validChainExitsZero() {
    assertEquals(
        AttestationCommand.EXIT_VALID,
        run(
            "--anchor",
            root.toString(),
            "--chain",
            sam.toString(),
            "--chain",
            f9.toString(),
            "--leaf",
            leaf.toString(),
            "--expect-opid",
            AttestationTestChains.SAMPLE_OPID.toPrinted(),
            "--at",
            AT));
    assertTrue(out.toString().contains("RESULT: VALID"), out.toString());
  }

  @Test
  void jsonReportIsPrinted() {
    assertEquals(AttestationCommand.EXIT_VALID, run(fullChain("--json")));
    assertTrue(out.toString().contains("\"valid\": true"), out.toString());
    assertTrue(out.toString().contains("\"checkId\": \"pkix.path\""), out.toString());
  }

  @Test
  void tamperedLeafExitsOne() throws Exception {
    write("leaf.pem", AttestationTestChains.pem(AttestationTestChains.tamperLastByte(chain.leaf)));
    assertEquals(AttestationCommand.EXIT_INVALID, run(fullChain()));
    assertTrue(out.toString().contains("RESULT: INVALID"), out.toString());
  }

  @Test
  void nonDerCertificateExitsOne() throws Exception {
    write(
        "f9.pem", AttestationTestChains.pem(AttestationTestChains.withNonMinimalLength(chain.f9)));
    assertEquals(AttestationCommand.EXIT_INVALID, run(fullChain()));
  }

  @Test
  void slotCertificateMismatchExitsOne() throws Exception {
    Path slot =
        write(
            "slot.pem",
            AttestationTestChains.pem(
                AttestationTestChains.selfSigned(AttestationTestChains.ecKey("secp256r1"))));
    assertEquals(AttestationCommand.EXIT_INVALID, run(fullChain("--slot-cert", slot.toString())));
  }

  @Test
  void expectedBuildIsChecked() {
    String build = hex(AttestationTestChains.BUILD_SHA256);
    assertEquals(AttestationCommand.EXIT_VALID, run(fullChain("--expect-build", build)));
    assertTrue(out.toString().contains("leaf.expect-build"), out.toString());
    String other = (build.charAt(0) == '0' ? "1" : "0") + build.substring(1);
    assertEquals(AttestationCommand.EXIT_INVALID, run(fullChain("--expect-build", other)));
    assertEquals(AttestationCommand.EXIT_USAGE, run(fullChain("--expect-build", "00")));
  }

  @Test
  void receiptSuppliesTheExpectedMeasurements() throws Exception {
    Path receipt = receipt(hex(AttestationTestChains.CAP_SHA256));
    assertEquals(AttestationCommand.EXIT_VALID, run(fullChain("--receipt", receipt.toString())));
    for (String id : new String[] {"f9.expect-cap", "f9.expect-cplc", "leaf.expect-build"}) {
      assertTrue(out.toString().matches("(?s).*PASS\\s+" + id.replace(".", "\\.") + "\\s.*"), id);
    }

    byte[] otherCap = AttestationTestChains.CAP_SHA256.clone();
    otherCap[0] ^= 1;
    Path tampered = receipt(hex(otherCap));
    assertEquals(AttestationCommand.EXIT_INVALID, run(fullChain("--receipt", tampered.toString())));
    assertEquals(
        AttestationCommand.EXIT_USAGE,
        run(fullChain("--receipt", receipt.toString(), "--expect-cap", hex(otherCap))));
  }

  private Path receipt(String capSha256) throws Exception {
    String json =
        "{\"schema\":\""
            + dev.mistial.tools.openfips201.issuance.IssuanceReceipt.SCHEMA
            + "\",\"cap\":{\"sha256\":\""
            + capSha256
            + "\",\"properties\":{\"build.sha256\":\""
            + hex(AttestationTestChains.BUILD_SHA256).toLowerCase(java.util.Locale.ROOT)
            + "\"}},\"card\":{\"cplcSha256\":\""
            + hex(AttestationTestChains.CPLC_SHA256)
            + "\"}}";
    return write("receipt-" + capSha256.substring(0, 8) + ".json", json);
  }

  private static String hex(byte[] value) {
    return dev.mistial.tools.openfips201.common.HexUtil.format(value);
  }

  @Test
  void dateOnlyEvaluationTimeIsAccepted() {
    List<String> args = new ArrayList<String>(Arrays.asList(fullChain()));
    args.set(args.indexOf(AT), "2026-06-01");
    assertEquals(AttestationCommand.EXIT_VALID, run(args.toArray(new String[0])));
  }

  @Test
  void missingAnchorExitsTwo() {
    assertEquals(AttestationCommand.EXIT_USAGE, run("--leaf", leaf.toString()));
  }

  @Test
  void malformedTimeExitsTwo() {
    List<String> args = new ArrayList<String>(Arrays.asList(fullChain()));
    args.set(args.indexOf(AT), "yesterday");
    assertEquals(AttestationCommand.EXIT_USAGE, run(args.toArray(new String[0])));
  }

  @Test
  void twoPemBlocksExitTwo() throws Exception {
    write(
        "root.pem", AttestationTestChains.pem(chain.root) + AttestationTestChains.pem(chain.root));
    assertEquals(AttestationCommand.EXIT_USAGE, run(fullChain()));
  }

  @Test
  void missingFileExitsTwo() {
    assertEquals(
        AttestationCommand.EXIT_USAGE,
        run("--anchor", dir.resolve("absent.pem").toString(), "--leaf", leaf.toString()));
  }

  @Test
  void threeChainCertificatesExitTwo() {
    assertEquals(AttestationCommand.EXIT_USAGE, run(fullChain("--chain", f9.toString())));
  }

  @Test
  void bareAttestationCommandExitsTwo() {
    StringWriter sink = new StringWriter();
    CommandLine commandLine = new CommandLine(new AttestationCommand());
    commandLine.setOut(new PrintWriter(sink));
    commandLine.setErr(new PrintWriter(sink));
    assertEquals(AttestationCommand.EXIT_USAGE, commandLine.execute());
  }

  private String[] fullChain(String... extra) {
    List<String> args =
        new ArrayList<String>(
            Arrays.asList(
                "--anchor",
                root.toString(),
                "--chain",
                sam.toString(),
                "--chain",
                f9.toString(),
                "--leaf",
                leaf.toString(),
                "--at",
                AT));
    args.addAll(Arrays.asList(extra));
    return args.toArray(new String[0]);
  }

  private int run(String... args) {
    out = new StringWriter();
    CommandLine commandLine = new CommandLine(new AttestationCommand());
    commandLine.setOut(new PrintWriter(out));
    commandLine.setErr(new PrintWriter(out));
    String[] full = new String[args.length + 1];
    full[0] = "verify";
    System.arraycopy(args, 0, full, 1, args.length);
    return commandLine.execute(full);
  }

  private Path write(String name, String content) throws Exception {
    Path path = dir.resolve(name);
    Files.write(path, content.getBytes(StandardCharsets.US_ASCII));
    return path;
  }
}
