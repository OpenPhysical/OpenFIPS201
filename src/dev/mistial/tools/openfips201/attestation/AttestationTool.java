/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.io.Console;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.Callable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "attestation-tool",
    mixinStandardHelpOptions = true,
    description = "Provision F9 attestation authority credentials for this applet.",
    subcommands = {
      AttestationTool.ListReaders.class,
      AttestationTool.ProbeScp.class,
      AttestationTool.PrepareCsr.class,
      AttestationTool.DirectProvision.class,
      AttestationTool.Provision.class,
      AttestationTool.Attest.class
    })
public final class AttestationTool implements Callable<Integer> {
  public static void main(String[] args) {
    CommandLine commandLine = new CommandLine(new AttestationTool());
    commandLine.setExecutionExceptionHandler(
        (exception, parsedCommand, parseResult) -> {
          parsedCommand.getErr().println("Error: " + exception.getMessage());
          return 1;
        });
    System.exit(commandLine.execute(args));
  }

  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(name = "list-readers", description = "List PC/SC reader names.")
  static final class ListReaders implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
      GlobalPlatformCardSession.listReaders();
      return 0;
    }
  }

  @Command(
      name = "probe-scp",
      description = "Select the PIV applet and open one SCP channel without provisioning.")
  static final class ProbeScp extends CardOptions implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
      try (GlobalPlatformCardSession session = (GlobalPlatformCardSession) openSession()) {
        System.out.println("SCP established: " + session.getScpMode().name());
      }
      return 0;
    }
  }

  @Command(name = "prepare-csr", description = "Generate a P-256 F9 key pair and CSR on the host.")
  static final class PrepareCsr implements Callable<Integer> {
    @Option(
        names = "--subject",
        required = true,
        description = "X.500 subject, for example CN=Device F9,O=Example")
    String subject;

    @Option(names = "--key-out", required = true, description = "Output PEM private key path.")
    Path keyOut;

    @Option(names = "--csr-out", required = true, description = "Output PEM CSR path.")
    Path csrOut;

    @Option(
        names = "--key-pass-env",
        description = "Environment variable containing the private-key encryption passphrase.")
    String keyPassEnv;

    @Option(
        names = "--no-private-key-encryption",
        description = "Write plaintext PKCS#8 private key.")
    boolean noPrivateKeyEncryption;

    @Override
    public Integer call() throws Exception {
      KeyPair keyPair = AttestationSupport.generateF9KeyPair();
      char[] passphrase =
          noPrivateKeyEncryption ? null : readPassphrase(keyPassEnv, "F9 private key passphrase");
      try {
        PKCS10CertificationRequest csr =
            AttestationSupport.createCsr(keyPair, new X500Name(subject));
        PemFiles.writePrivateKey(keyOut, keyPair.getPrivate(), passphrase);
        PemFiles.writeObject(csrOut, csr);
        System.out.println("Wrote " + keyOut);
        System.out.println("Wrote " + csrOut);
      } finally {
        clear(passphrase);
      }
      return 0;
    }
  }

  @Command(
      name = "direct-provision",
      description =
          "Generate a local F9 issuer certificate and provision the card in one operation.")
  static final class DirectProvision extends CardOptions implements Callable<Integer> {
    @Option(names = "--subject", required = true, description = "X.500 issuer subject.")
    String subject;

    @Option(names = "--not-before", required = true, description = "UTC date, yyyy-MM-dd.")
    String notBefore;

    @Option(names = "--not-after", required = true, description = "UTC date, yyyy-MM-dd.")
    String notAfter;

    @Option(
        names = "--issuer-cert-out",
        required = true,
        description = "Output PEM issuer certificate path.")
    Path issuerCertOut;

    @Option(
        names = "--issuer-key-out",
        required = true,
        description = "Output PEM F9 private key path.")
    Path issuerKeyOut;

    @Option(
        names = "--issuer-key-pass-env",
        description = "Environment variable containing key encryption passphrase.")
    String issuerKeyPassEnv;

    @Option(
        names = "--no-private-key-encryption",
        description = "Write plaintext issuer private key.")
    boolean noPrivateKeyEncryption;

    @Override
    public Integer call() throws Exception {
      KeyPair keyPair = AttestationSupport.generateF9KeyPair();
      X509Certificate certificate =
          AttestationSupport.createIssuerCertificate(
              keyPair, new X500Name(subject), utcDate(notBefore), utcDate(notAfter));
      char[] passphrase =
          noPrivateKeyEncryption
              ? null
              : readPassphrase(issuerKeyPassEnv, "F9 issuer private key passphrase");
      try {
        PemFiles.writePrivateKey(issuerKeyOut, keyPair.getPrivate(), passphrase);
        PemFiles.writeObject(issuerCertOut, certificate);
        F9Profile profile = AttestationSupport.profileFromIssuer(keyPair.getPrivate(), certificate);
        try (CardSession session = openSession()) {
          OpenFips201Provisioner.provisionAuthority(
              session, profile, AttestationSupport.der(certificate), issuerObjectId());
        }
      } finally {
        clear(passphrase);
      }
      return 0;
    }
  }

  @Command(
      name = "provision",
      description = "Provision the card from an existing F9 private key and issuer certificate.")
  static final class Provision extends CardOptions implements Callable<Integer> {
    @Option(names = "--issuer-key", required = true, description = "PEM F9 private key path.")
    Path issuerKey;

    @Option(
        names = "--issuer-cert",
        required = true,
        description = "PEM F9 issuer certificate path.")
    Path issuerCert;

    @Option(
        names = "--issuer-key-pass-env",
        description = "Environment variable containing key decryption passphrase.")
    String issuerKeyPassEnv;

    @Override
    public Integer call() throws Exception {
      char[] passphrase = readOptionalPassphrase(issuerKeyPassEnv);
      try {
        PrivateKey privateKey = PemFiles.readPrivateKey(issuerKey, passphrase);
        X509Certificate certificate = PemFiles.readCertificate(issuerCert);
        F9Profile profile = AttestationSupport.profileFromIssuer(privateKey, certificate);
        try (CardSession session = openSession()) {
          OpenFips201Provisioner.provisionAuthority(
              session, profile, AttestationSupport.der(certificate), issuerObjectId());
        }
      } finally {
        clear(passphrase);
      }
      return 0;
    }
  }

  static class CardOptions {
    @Option(names = "--reader", description = "Substring of the PC/SC reader name.")
    String reader;

    @Option(
        names = "--scp",
        defaultValue = "auto",
        description = "Secure channel version: auto queries card key info; or force 02/03.")
    String scp;

    @Option(
        names = "--scp-key-version",
        defaultValue = "0",
        description = "GlobalPlatform SCP key version.")
    int scpKeyVersion;

    @Option(names = "--scp-key", description = "Static ENC/MAC/DEK key as hex.")
    String scpKey;

    @Option(names = "--scp-enc-key", description = "ENC key as hex.")
    String scpEncKey;

    @Option(names = "--scp-mac-key", description = "MAC key as hex.")
    String scpMacKey;

    @Option(names = "--scp-dek-key", description = "DEK key as hex.")
    String scpDekKey;

    @Option(
        names = "--piv-aid",
        defaultValue = "A000000308000010000100",
        description = "PIV applet AID hex.")
    String pivAid;

    @Option(
        names = "--issuer-object-id",
        defaultValue = AttestationSupport.DEFAULT_ISSUER_OBJECT_ID_HEX,
        description = "PIV object ID for issuer certificate.")
    String issuerObjectId;

    CardSession openSession() throws Exception {
      byte[][] keys = scpKeys();
      return GlobalPlatformCardSession.open(
          reader,
          scpMode(),
          scpKeyVersion,
          keys[0],
          keys[1],
          keys[2],
          AttestationSupport.hex(pivAid));
    }

    byte[] issuerObjectId() {
      return AttestationSupport.hex(issuerObjectId);
    }

    private byte[][] scpKeys() {
      if (scpKey != null) {
        byte[] key = AttestationSupport.hex(scpKey);
        return new byte[][] {key, key, key};
      }
      if (scpEncKey == null || scpMacKey == null || scpDekKey == null) {
        throw new IllegalArgumentException(
            "Provide --scp-key or all of --scp-enc-key, --scp-mac-key, --scp-dek-key");
      }
      return new byte[][] {
        AttestationSupport.hex(scpEncKey),
        AttestationSupport.hex(scpMacKey),
        AttestationSupport.hex(scpDekKey)
      };
    }

    private GlobalPlatformCardSession.ScpMode scpMode() {
      if ("auto".equalsIgnoreCase(scp)) {
        return GlobalPlatformCardSession.ScpMode.AUTO;
      }
      if ("02".equals(scp) || "2".equals(scp) || "scp02".equalsIgnoreCase(scp)) {
        return GlobalPlatformCardSession.ScpMode.SCP02;
      }
      if ("03".equals(scp) || "3".equals(scp) || "scp03".equalsIgnoreCase(scp)) {
        return GlobalPlatformCardSession.ScpMode.SCP03;
      }
      throw new IllegalArgumentException("--scp must be auto, 02, or 03");
    }
  }

  private static Date utcDate(String value) {
    return Date.from(LocalDate.parse(value).atStartOfDay().toInstant(ZoneOffset.UTC));
  }

  private static char[] readOptionalPassphrase(String env) {
    if (env == null || env.isEmpty()) {
      return null;
    }
    return requireNonEmptyPassphrase(requireEnv(env).toCharArray(), env);
  }

  private static char[] readPassphrase(String env, String prompt) {
    if (env != null && !env.isEmpty()) {
      return requireNonEmptyPassphrase(requireEnv(env).toCharArray(), env);
    }
    Console console = System.console();
    if (console == null) {
      throw new IllegalArgumentException(
          "No console available; pass --*-pass-env or --no-private-key-encryption");
    }
    char[] first = console.readPassword("%s: ", prompt);
    char[] second = console.readPassword("Confirm %s: ", prompt);
    if (!Arrays.equals(first, second)) {
      clear(first);
      clear(second);
      throw new IllegalArgumentException("Passphrases did not match");
    }
    clear(second);
    return requireNonEmptyPassphrase(first, prompt);
  }

  private static String requireEnv(String name) {
    String value = System.getenv(name);
    if (value == null) {
      throw new IllegalArgumentException("Environment variable is not set: " + name);
    }
    return value;
  }

  private static void clear(char[] value) {
    if (value != null) {
      Arrays.fill(value, '\0');
    }
  }

  static char[] requireNonEmptyPassphrase(char[] value, String source) {
    if (value == null || value.length == 0) {
      clear(value);
      throw new IllegalArgumentException("Empty passphrase is not allowed for " + source);
    }
    return value;
  }

  @Command(
      name = "attest",
      description = "Request an attestation certificate for a generated target key (INS F9).")
  static final class Attest extends CardOptions implements Callable<Integer> {
    @Option(
        names = "--slot",
        defaultValue = "9A",
        description = "PIV target slot hex, for example 9A or 82.")
    String slot;

    @Option(names = "--out", description = "Output path for the raw DER certificate.")
    Path out;

    @Override
    public Integer call() throws Exception {
      byte slotByte = (byte) Integer.parseInt(slot, 16);
      try (CardSession session = openSession()) {
        ResponseAPDU response =
            session.transmit(new CommandAPDU(0x00, 0xF9, slotByte & 0xFF, 0x00, 0));
        byte[] certificate = collectResponse(response, session);
        System.out.println("certificate: " + certificate.length + " bytes");
        if (out != null) {
          java.nio.file.Files.write(out, certificate);
          System.out.println("wrote " + out);
        }
        return 0;
      }
    }

    private static byte[] collectResponse(ResponseAPDU initial, CardSession session)
        throws Exception {
      java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
      ResponseAPDU current = initial;
      while ((current.getSW() & 0xFF00) == 0x6100) {
        output.write(current.getData());
        int le = current.getSW() & 0xFF;
        current = session.transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le == 0 ? 256 : le));
      }
      if (current.getSW() != 0x9000) {
        throw new IllegalStateException(
            String.format(
                "INS F9 failed, SW=0x%04X (see docs/ATTESTATION.md status words)",
                current.getSW()));
      }
      output.write(current.getData());
      return output.toByteArray();
    }
  }
}
