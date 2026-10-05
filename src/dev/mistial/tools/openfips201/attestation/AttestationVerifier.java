/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions.F9Issuance;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions.PivLeaf;
import dev.mistial.tools.openfips201.attestation.OpenPhysicalExtensions.SamBatch;
import dev.mistial.tools.openfips201.attestation.VerificationReport.Entry;
import dev.mistial.tools.openfips201.attestation.VerificationReport.Status;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.opid.ChuidIdentityCheck;
import dev.mistial.tools.openfips201.opid.Opid;
import dev.mistial.tools.openfips201.opid.OpidSequence;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;

/**
 * Offline verifier for an OpenPhysical attestation chain: root (trust anchor), SAM certificate,
 * per-card F9 attestation authority certificate and PIV attestation leaf.
 *
 * <p>{@link #verify} is fail-closed: every check runs in isolation, any exception raised inside a
 * check is recorded as {@link Status#FAIL}, and no exception escapes. A check is {@link
 * Status#SKIP} only when its optional input was not supplied, or when a prerequisite (for example
 * the strict DER parse of the certificate it inspects) has already been recorded as a failure.
 */
public final class AttestationVerifier {
  // Check identifiers, in evaluation order.
  public static final String DER_ROOT = "der.root";
  public static final String DER_SAM = "der.sam";
  public static final String DER_F9 = "der.f9";
  public static final String DER_LEAF = "der.leaf";
  public static final String DER_SLOT = "der.slot";
  public static final String CHAIN_STRUCTURE = "chain.structure";
  public static final String SIGALG_ROOT = "sigalg.root";
  public static final String SIGALG_SAM = "sigalg.sam";
  public static final String SIGALG_F9 = "sigalg.f9";
  public static final String SIGALG_LEAF = "sigalg.leaf";
  public static final String PKIX_PATH = "pkix.path";
  public static final String ROOT_SELF_SIGNED = "root.self-signed";
  public static final String ROOT_BASIC_CONSTRAINTS = "root.basic-constraints";
  public static final String ROOT_SKI = "root.ski";
  public static final String SAM = "sam";
  public static final String SAM_SIGNATURE = "sam.signature";
  public static final String SAM_BASIC_CONSTRAINTS = "sam.basic-constraints";
  public static final String SAM_KEY_USAGE = "sam.key-usage";
  public static final String SAM_SKI = "sam.ski";
  public static final String SAM_AKI = "sam.aki";
  public static final String SAM_ISSUER = "sam.issuer";
  public static final String SAM_VALIDITY = "sam.validity";
  public static final String SAM_BATCH_EXTENSION = "sam.batch-extension";
  public static final String SAM_REGISTRY = "sam.registry";
  public static final String F9 = "f9";
  public static final String F9_SIGNATURE = "f9.signature";
  public static final String F9_BASIC_CONSTRAINTS = "f9.basic-constraints";
  public static final String F9_KEY_USAGE = "f9.key-usage";
  public static final String F9_SKI = "f9.ski";
  public static final String F9_AKI = "f9.aki";
  public static final String F9_ISSUER = "f9.issuer";
  public static final String F9_OPID = "f9.opid";
  public static final String F9_OPID_BATCH = "f9.opid-batch";
  public static final String F9_VALIDITY = "f9.validity";
  public static final String F9_ISSUANCE_EXTENSION = "f9.issuance-extension";
  public static final String F9_LCG_AUDIT = "f9.lcg-audit";
  public static final String F9_EXPECT_OPID = "f9.expect-opid";
  public static final String F9_NOT_VOIDED = "f9.not-voided";
  public static final String LEAF = "leaf";
  public static final String LEAF_SIGNATURE = "leaf.signature";
  public static final String LEAF_BASIC_CONSTRAINTS = "leaf.basic-constraints";
  public static final String LEAF_ISSUER = "leaf.issuer";
  public static final String LEAF_AKI = "leaf.aki";
  public static final String LEAF_VALIDITY = "leaf.validity";
  public static final String LEAF_EXTENSION = "leaf.extension";
  public static final String LEAF_ORIGIN = "leaf.origin";
  public static final String LEAF_KEY_REFERENCE = "leaf.key-reference";
  public static final String LEAF_KEY_USAGE = "leaf.key-usage";
  public static final String LEAF_SLOT_SPKI = "leaf.slot-spki";
  public static final String CHUID_IDENTITY = "chuid.identity";
  public static final String INTERNAL = "verifier.internal";

  /** {@code PIVKeyObject.ROLE_KEY_ESTABLISH}: ECDH or RSA key transport. */
  public static final int ROLE_KEY_ESTABLISH = 0x02;

  /** {@code PIVKeyObject.ROLE_SIGN}: ECDSA or RSA digital signature. */
  public static final int ROLE_SIGN = 0x04;

  /** Common name prefix of the leaf subject {@code CN=PIV Attestation XX}. */
  public static final String LEAF_CN_PREFIX = "PIV Attestation ";

  /** Length of an RFC 7093 method 1 key identifier: the leftmost 160 bits of SHA-256. */
  public static final int KEY_IDENTIFIER_LENGTH = 20;

  static final ASN1ObjectIdentifier ECDSA_WITH_SHA256 =
      new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
  static final ASN1ObjectIdentifier ECDSA_WITH_SHA384 =
      new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
  static final ASN1ObjectIdentifier ID_EC_PUBLIC_KEY =
      new ASN1ObjectIdentifier("1.2.840.10045.2.1");
  static final ASN1ObjectIdentifier RSA_ENCRYPTION =
      new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
  static final ASN1ObjectIdentifier P256 = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
  static final ASN1ObjectIdentifier P384 = new ASN1ObjectIdentifier("1.3.132.0.34");
  static final ASN1ObjectIdentifier COMMON_NAME = new ASN1ObjectIdentifier("2.5.4.3");

  /** DER keyUsage BIT STRING {@code keyCertSign} only, as fixed by the F9 profile. */
  private static final byte[] KEY_USAGE_KEY_CERT_SIGN_ONLY = {0x03, 0x02, 0x02, 0x04};

  private AttestationVerifier() {}

  /** Runs every check against {@code request}; never throws. */
  public static VerificationReport verify(VerificationRequest request) {
    Run run = new Run();
    try {
      run.execute(request);
    } catch (Exception e) {
      run.entries.add(new Entry(INTERNAL, Status.FAIL, describe(e)));
    }
    return new VerificationReport(run.entries);
  }

  /** RFC 7093 Section 2 method 1 over the subjectPublicKey BIT STRING value. */
  public static byte[] keyIdentifierMethod1(SubjectPublicKeyInfo spki) {
    return KeyIdentifiers.ski(spki);
  }

  /** A check body: returns the PASS detail, or throws to record FAIL ({@link Skip} for SKIP). */
  private interface Check {
    String run() throws Exception;
  }

  /** Raised inside a check to record SKIP. */
  private static final class Skip extends Exception {
    private static final long serialVersionUID = 1L;

    Skip(String message) {
      super(message);
    }
  }

  /** A supplied certificate; {@link #jdk} and {@link #bc} are null when strict parsing failed. */
  private static final class Cert {
    final String name;
    final String derCheck;
    final byte[] der;
    X509Certificate jdk;
    Certificate bc;

    Cert(String name, String derCheck, byte[] der) {
      this.name = name;
      this.derCheck = derCheck;
      this.der = der;
    }

    Extensions extensions() {
      return bc.getTBSCertificate().getExtensions();
    }

    byte[] subjectDer() throws IOException {
      return bc.getSubject().getEncoded(ASN1Encoding.DER);
    }

    byte[] issuerDer() throws IOException {
      return bc.getIssuer().getEncoded(ASN1Encoding.DER);
    }

    byte[] spkiDer() throws IOException {
      return bc.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER);
    }
  }

  /** State of one {@link #verify} call. */
  private static final class Run {
    final List<Entry> entries = new ArrayList<Entry>();
    VerificationRequest request;
    Cert root;
    Cert sam;
    Cert f9;
    Cert leaf;
    Cert slot;
    SamBatch samBatch;
    Opid opid;
    F9Issuance issuance;
    PivLeaf pivLeaf;

    void execute(VerificationRequest req) {
      this.request = req;
      root = parse(new Cert("root", DER_ROOT, req.anchor()));
      sam =
          req.samCertificate().isPresent()
              ? parse(new Cert("SAM", DER_SAM, req.samCertificate().get()))
              : null;
      f9 =
          req.f9Certificate().isPresent()
              ? parse(new Cert("F9", DER_F9, req.f9Certificate().get()))
              : null;
      leaf = req.leaf().isPresent() ? parse(new Cert("leaf", DER_LEAF, req.leaf().get())) : null;
      slot =
          req.slotCertificate().isPresent()
              ? parse(new Cert("slot", DER_SLOT, req.slotCertificate().get()))
              : null;

      check(CHAIN_STRUCTURE, this::chainStructure);
      check(SIGALG_ROOT, () -> caSignatureAlgorithm(root, false));
      if (sam != null) {
        check(SIGALG_SAM, () -> caSignatureAlgorithm(sam, false));
      }
      if (f9 != null) {
        check(SIGALG_F9, () -> caSignatureAlgorithm(f9, true));
      }
      if (leaf != null) {
        check(SIGALG_LEAF, this::leafSignatureAlgorithm);
      }
      check(PKIX_PATH, this::pkixPath);
      rootChecks();
      if (sam == null) {
        skip(SAM, "no SAM certificate supplied");
      } else {
        samChecks();
      }
      if (f9 == null) {
        skip(F9, "no F9 certificate supplied");
      } else {
        f9Checks();
      }
      check(SAM_REGISTRY, this::registry);
      check(F9_LCG_AUDIT, this::lcgAudit);
      check(F9_EXPECT_OPID, this::expectOpid);
      check(F9_NOT_VOIDED, this::notVoided);
      if (leaf == null) {
        skip(LEAF, "no leaf certificate supplied");
      } else {
        leafChecks();
      }
      check(LEAF_SLOT_SPKI, this::slotSpki);
      check(CHUID_IDENTITY, this::chuid);
    }

    Cert parse(final Cert cert) {
      check(
          cert.derCheck,
          () -> {
            X509Certificate parsed = StrictDer.parseCertificate(cert.der);
            Certificate structure = Certificate.getInstance(cert.der);
            cert.jdk = parsed;
            cert.bc = structure;
            return cert.der.length + " bytes, subject " + structure.getSubject();
          });
      return cert;
    }

    void check(String id, Check body) {
      Status status;
      String detail;
      try {
        detail = body.run();
        status = Status.PASS;
      } catch (Skip e) {
        status = Status.SKIP;
        detail = e.getMessage();
      } catch (Exception e) {
        status = Status.FAIL;
        detail = describe(e);
      }
      entries.add(new Entry(id, status, detail));
    }

    void skip(String id, String reason) {
      entries.add(new Entry(id, Status.SKIP, reason));
    }

    // ---- structure, algorithms and path ----

    String chainStructure() {
      StringBuilder path = new StringBuilder("root");
      if (sam != null) {
        path.append(" -> SAM");
      }
      if (f9 != null) {
        require(sam != null, "an F9 certificate requires the SAM certificate that issued it");
        path.append(" -> F9");
      }
      if (leaf != null) {
        require(f9 != null, "a leaf certificate requires the F9 certificate that issued it");
        path.append(" -> leaf");
      }
      return path.toString();
    }

    /**
     * CA certificates: ecdsa-with-SHA256 or ecdsa-with-SHA384 with absent parameters (RFC 5758
     * Section 3.2) and a subject key on P-256 or P-384. The F9 key is fixed to P-256.
     */
    String caSignatureAlgorithm(Cert cert, boolean requireP256) throws Skip {
      need(cert);
      ASN1ObjectIdentifier algorithm = signatureAlgorithm(cert);
      require(
          ECDSA_WITH_SHA256.equals(algorithm) || ECDSA_WITH_SHA384.equals(algorithm),
          cert.name + " signature algorithm " + algorithm + " is not ecdsa-with-SHA256/384");
      ASN1ObjectIdentifier curve = ecCurve(cert);
      require(curve != null, cert.name + " public key is not an EC named-curve key");
      if (requireP256) {
        require(P256.equals(curve), cert.name + " public key must be on P-256, found " + curve);
      } else {
        require(
            P256.equals(curve) || P384.equals(curve),
            cert.name + " public key must be on P-256 or P-384, found " + curve);
      }
      return algorithm + " / " + curve;
    }

    /** The leaf may carry any key type but is signed by F9 with ecdsa-with-SHA256. */
    String leafSignatureAlgorithm() throws Skip {
      need(leaf);
      ASN1ObjectIdentifier algorithm = signatureAlgorithm(leaf);
      require(
          ECDSA_WITH_SHA256.equals(algorithm),
          "leaf signature algorithm " + algorithm + " is not ecdsa-with-SHA256");
      return algorithm.getId();
    }

    String pkixPath() throws Exception {
      need(root);
      List<X509Certificate> path = new ArrayList<X509Certificate>();
      for (Cert cert : new Cert[] {leaf, f9, sam}) {
        if (cert != null) {
          need(cert);
          path.add(cert.jdk);
        }
      }
      if (path.isEmpty()) {
        throw new Skip("no certificate below the trust anchor");
      }
      CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(path);
      PKIXParameters parameters =
          new PKIXParameters(Collections.singleton(new TrustAnchor(root.jdk, null)));
      parameters.setRevocationEnabled(false);
      parameters.setDate(request.at());
      try {
        CertPathValidator.getInstance("PKIX").validate(certPath, parameters);
      } catch (CertPathValidatorException e) {
        throw new IllegalStateException(
            "PKIX rejected the path at index " + e.getIndex() + ": " + e.getMessage(), e);
      }
      return path.size() + " certificate(s) valid at " + request.at().toInstant();
    }

    // ---- root ----

    void rootChecks() {
      check(
          ROOT_SELF_SIGNED,
          () -> {
            need(root);
            require(
                Arrays.equals(root.issuerDer(), root.subjectDer()),
                "root issuer differs from its subject");
            root.jdk.verify(root.jdk.getPublicKey());
            return "issuer == subject; signature verifies under its own key";
          });
      check(
          ROOT_BASIC_CONSTRAINTS,
          () -> {
            need(root);
            BasicConstraints bc = BasicConstraints.fromExtensions(root.extensions());
            require(bc != null && bc.isCA(), "root basicConstraints cA is not TRUE");
            return "cA TRUE";
          });
      check(ROOT_SKI, () -> hex(requireSki(root)));
    }

    // ---- SAM ----

    void samChecks() {
      check(SAM_SIGNATURE, () -> signedBy(sam, root));
      check(SAM_BASIC_CONSTRAINTS, () -> caBasicConstraints(sam, 1));
      check(
          SAM_KEY_USAGE,
          () -> {
            need(sam);
            Extension extension = requireCritical(sam, Extension.keyUsage, "keyUsage");
            KeyUsage usage = KeyUsage.getInstance(extension.getParsedValue());
            require(usage.hasUsages(KeyUsage.keyCertSign), "SAM keyUsage lacks keyCertSign");
            return "critical, includes keyCertSign";
          });
      check(SAM_SKI, () -> hex(requireSki(sam)));
      check(SAM_AKI, () -> akiMatches(sam, root));
      check(SAM_ISSUER, () -> issuerMatches(sam, root));
      check(SAM_VALIDITY, () -> validityWithin(sam, root));
      check(
          SAM_BATCH_EXTENSION,
          () -> {
            need(sam);
            SamBatch batch =
                OpenPhysicalExtensions.parseSamBatch(
                    OpenPhysicalExtensions.requireNonCritical(
                        sam.extensions(), OpenPhysicalExtensions.SAM_BATCH));
            samBatch = batch;
            return "issuerId "
                + batch.issuerId
                + ", batch "
                + batch.batch
                + ", initialQuota "
                + batch.initialQuota;
          });
    }

    // ---- F9 ----

    void f9Checks() {
      check(F9_SIGNATURE, () -> signedBy(f9, sam));
      check(F9_BASIC_CONSTRAINTS, () -> caBasicConstraints(f9, 0));
      check(
          F9_KEY_USAGE,
          () -> {
            need(f9);
            Extension extension = requireCritical(f9, Extension.keyUsage, "keyUsage");
            require(
                Arrays.equals(extension.getExtnValue().getOctets(), KEY_USAGE_KEY_CERT_SIGN_ONLY),
                "F9 keyUsage must be exactly keyCertSign");
            return "critical, keyCertSign only";
          });
      check(
          F9_SKI,
          () -> {
            need(f9);
            byte[] ski = requireSki(f9);
            byte[] expected = keyIdentifierMethod1(f9.bc.getSubjectPublicKeyInfo());
            require(
                Arrays.equals(ski, expected),
                "F9 subjectKeyIdentifier "
                    + hex(ski)
                    + " is not the RFC 7093 method 1 value "
                    + hex(expected));
            return hex(ski) + " (RFC 7093 method 1)";
          });
      check(F9_AKI, () -> akiMatches(f9, sam));
      check(F9_ISSUER, () -> issuerMatches(f9, sam));
      check(
          F9_OPID,
          () -> {
            need(f9);
            Opid parsed = F9SubjectNames.extractOpid(f9.bc.getSubject());
            opid = parsed;
            return parsed.toPrinted();
          });
      check(
          F9_OPID_BATCH,
          () -> {
            if (opid == null) {
              throw new Skip("F9 OPID unavailable");
            }
            if (samBatch == null) {
              throw new Skip("SAM batch extension unavailable");
            }
            // The batch is enciphered inside E, so only the plaintext IIN is comparable.
            require(
                opid.iin == samBatch.issuerId,
                "OPID IIN " + opid.iin + " != SAM issuerId " + samBatch.issuerId);
            return "IIN " + opid.iin + " matches the SAM batch extension issuerId";
          });
      check(F9_VALIDITY, () -> validityWithin(f9, sam));
      check(
          F9_ISSUANCE_EXTENSION,
          () -> {
            need(f9);
            F9Issuance parsed =
                OpenPhysicalExtensions.parseF9Issuance(
                    OpenPhysicalExtensions.requireNonCritical(
                        f9.extensions(), OpenPhysicalExtensions.F9_ISSUANCE));
            issuance = parsed;
            return "issuanceSeq " + parsed.issuanceSeq + ", eventSeq " + parsed.eventSeq;
          });
    }

    /**
     * Issuance number {@code n >= 1} receives {@code sequence.opidAt(n)}; n is the issuanceSeq of
     * the F9 issuance extension.
     */
    String lcgAudit() throws Skip {
      OpidSequence sequence = request.sequence().orElse(null);
      if (sequence == null) {
        if (request.issuanceSeq().isPresent()) {
          throw new IllegalArgumentException("an expected issuanceSeq requires an OPID sequence");
        }
        throw new Skip("no OPID sequence supplied");
      }
      require(f9 != null, "OPID audit requested but no F9 certificate supplied");
      if (opid == null) {
        throw new Skip("F9 OPID unavailable");
      }
      if (issuance == null) {
        throw new Skip("F9 issuance extension unavailable");
      }
      long seq = issuance.issuanceSeq;
      if (request.issuanceSeq().isPresent()) {
        require(
            request.issuanceSeq().get() == seq,
            "issuanceSeq " + seq + " != expected " + request.issuanceSeq().get());
      }
      require(seq >= 1, "issuanceSeq must be >= 1");
      Opid expected = sequence.opidAt(seq);
      require(
          opid.equals(expected),
          "OPID " + opid.toPrinted() + " != opidAt(" + seq + ") = " + expected.toPrinted());
      return "OPID " + opid.toPrinted() + " == opidAt(" + seq + ")";
    }

    /**
     * The registry ({@code allocations.jsonl}) verifies under the anchor line by line and chain;
     * its {@code allocate} line at the SAM's allocationSeq names the SAM's IIN, batch and initial
     * quota; a {@code bind} line for that allocation names the SAM's samId (its subject
     * serialNumber), and its SHA-256 is the certificate's registryHead.
     */
    String registry() throws Skip {
      List<String> lines = request.registry().orElse(null);
      if (lines == null) {
        throw new Skip("no registry supplied");
      }
      require(sam != null, "registry supplied but no SAM certificate supplied");
      if (samBatch == null) {
        throw new Skip("SAM batch extension unavailable");
      }
      dev.mistial.tools.openfips201.issuance.AllocationRegistry.verifyChain(
          lines, root.jdk.getPublicKey());
      require(samBatch.allocationSeq < lines.size(), "allocationSeq is beyond the registry");
      com.google.gson.JsonObject allocate =
          com.google.gson.JsonParser.parseString(lines.get((int) samBatch.allocationSeq))
              .getAsJsonObject();
      require(
          "allocate".equals(allocate.get("type").getAsString())
              && allocate.get("iin").getAsInt() == samBatch.issuerId
              && allocate.get("batch").getAsInt() == samBatch.batch
              && allocate.get("quota").getAsLong() == samBatch.initialQuota,
          "registry line " + samBatch.allocationSeq + " is not this SAM's allocation");
      String samId = samSerialNumber();
      for (String text : lines) {
        com.google.gson.JsonObject line =
            com.google.gson.JsonParser.parseString(text).getAsJsonObject();
        if ("bind".equals(line.get("type").getAsString())
            && line.get("allocationSeq").getAsLong() == samBatch.allocationSeq) {
          require(
              line.get("samId").getAsString().equals(samId),
              "the allocation is bound to SAM " + line.get("samId").getAsString());
          require(
              Arrays.equals(
                  dev.mistial.tools.openfips201.issuance.AllocationRegistry.headAfter(text),
                  samBatch.registryHead()),
              "the bind line is not the registryHead the SAM certificate records");
          return "allocation " + samBatch.allocationSeq + " bound to SAM " + samId;
        }
      }
      throw new IllegalStateException("the allocation is not bound to any SAM in the registry");
    }

    private String samSerialNumber() {
      org.bouncycastle.asn1.x500.RDN[] rdns =
          sam.bc.getSubject().getRDNs(F9SubjectNames.SERIAL_NUMBER);
      require(rdns.length == 1, "the SAM subject has no single serialNumber (samId)");
      return org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(
          rdns[0].getFirst().getValue());
    }

    /** The F9 OPID is not among the VOID entries signed by the SAM key. */
    String notVoided() throws Skip {
      List<VerificationRequest.SignedVoid> voids = request.voids().orElse(null);
      if (voids == null) {
        throw new Skip("no voids supplied");
      }
      if (opid == null || sam == null) {
        throw new Skip("F9 OPID or SAM certificate unavailable");
      }
      int signed = 0;
      for (VerificationRequest.SignedVoid candidate : voids) {
        dev.mistial.tools.openfips201.issuance.SamLedgerEntry.Signed entry;
        try {
          entry =
              new dev.mistial.tools.openfips201.issuance.SamLedgerEntry.Signed(
                  dev.mistial.tools.openfips201.issuance.SamLedgerEntry.parse(candidate.entry()),
                  candidate.signature());
        } catch (RuntimeException malformed) {
          continue;
        }
        if (entry.entry.type != dev.mistial.tools.openfips201.issuance.SamLedgerEntry.TYPE_VOID
            || !entry.verify(sam.jdk.getPublicKey())) {
          continue;
        }
        signed++;
        require(
            !opid.toPrinted().equals(entry.entry.opid),
            "OPID "
                + opid.toPrinted()
                + " was voided by the SAM (issuance "
                + entry.entry.issuanceSeq
                + ", reason "
                + entry.entry.reason
                + ")");
      }
      return "not among " + signed + " VOID entries signed by this SAM";
    }

    String expectOpid() throws Skip {
      Opid expected = request.expectOpid().orElse(null);
      if (expected == null) {
        throw new Skip("no expected OPID supplied");
      }
      require(f9 != null, "expected OPID supplied but no F9 certificate supplied");
      if (opid == null) {
        throw new Skip("F9 OPID unavailable");
      }
      require(opid.equals(expected), "F9 OPID " + opid + " != expected " + expected);
      return opid.toPrinted();
    }

    // ---- leaf ----

    void leafChecks() {
      check(LEAF_SIGNATURE, () -> signedBy(leaf, f9));
      check(
          LEAF_BASIC_CONSTRAINTS,
          () -> {
            need(leaf);
            BasicConstraints bc = BasicConstraints.fromExtensions(leaf.extensions());
            require(bc == null || !bc.isCA(), "leaf basicConstraints cA is TRUE");
            return bc == null ? "absent" : "cA FALSE";
          });
      check(LEAF_ISSUER, () -> issuerMatches(leaf, f9));
      check(LEAF_AKI, () -> akiMatches(leaf, f9));
      check(LEAF_VALIDITY, () -> validityWithin(leaf, f9));
      check(
          LEAF_EXTENSION,
          () -> {
            need(leaf);
            PivLeaf parsed =
                OpenPhysicalExtensions.parsePivLeaf(
                    OpenPhysicalExtensions.requireNonCritical(
                        leaf.extensions(), OpenPhysicalExtensions.PIV_LEAF));
            pivLeaf = parsed;
            return String.format(
                Locale.ROOT,
                "slot %02X, mechanism %02X, role %02X, attributes %02X, buildFlags %02X, vciSuite"
                    + " %02X, appletVersion %s, platformId %s",
                parsed.keyReference,
                parsed.mechanism,
                parsed.role,
                parsed.attributes,
                parsed.buildFlags,
                parsed.vciSuite,
                hex(parsed.appletVersion()),
                hex(parsed.platformId()));
          });
      check(
          LEAF_ORIGIN,
          () -> {
            requireLeafExtension();
            require(
                pivLeaf.origin == OpenPhysicalExtensions.ORIGIN_GENERATED,
                "leaf key origin " + pivLeaf.origin + " is not generated (2)");
            return "generated";
          });
      check(
          LEAF_KEY_REFERENCE,
          () -> {
            requireLeafExtension();
            String expected =
                LEAF_CN_PREFIX + String.format(Locale.ROOT, "%02X", pivLeaf.keyReference);
            String actual = singleCommonName(leaf);
            require(
                expected.equals(actual),
                "leaf subject CN '" + actual + "' does not name slot " + expected);
            return actual;
          });
      check(LEAF_KEY_USAGE, this::leafKeyUsage);
    }

    /**
     * Mirrors {@code PIVAttestation.keyUsageFor}: a ROLE_SIGN key carries digitalSignature only;
     * otherwise a ROLE_KEY_ESTABLISH key carries keyEncipherment (RSA) or keyAgreement (EC). The
     * extension must be critical and assert exactly that one bit.
     */
    String leafKeyUsage() throws Exception {
      requireLeafExtension();
      Extension extension = requireCritical(leaf, Extension.keyUsage, "keyUsage");
      int actual = DERBitString.getInstance(extension.getParsedValue()).intValue();
      ASN1ObjectIdentifier keyType =
          leaf.bc.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
      int expected;
      String name;
      if ((pivLeaf.role & ROLE_SIGN) != 0) {
        expected = KeyUsage.digitalSignature;
        name = "digitalSignature";
      } else if ((pivLeaf.role & ROLE_KEY_ESTABLISH) != 0) {
        if (RSA_ENCRYPTION.equals(keyType)) {
          expected = KeyUsage.keyEncipherment;
          name = "keyEncipherment";
        } else if (ID_EC_PUBLIC_KEY.equals(keyType)) {
          expected = KeyUsage.keyAgreement;
          name = "keyAgreement";
        } else {
          throw new IllegalArgumentException("leaf key type " + keyType + " is not RSA or EC");
        }
      } else {
        throw new IllegalArgumentException(
            String.format(
                Locale.ROOT, "leaf role %02X permits no attested key usage", pivLeaf.role));
      }
      require(
          actual == expected,
          String.format(
              Locale.ROOT,
              "leaf keyUsage %04X is inconsistent with role %02X (expected %s only)",
              actual,
              pivLeaf.role,
              name));
      return "critical, " + name + " only";
    }

    String slotSpki() throws Exception {
      if (slot == null) {
        throw new Skip("no slot certificate supplied");
      }
      require(leaf != null, "slot certificate supplied but no leaf certificate supplied");
      need(slot);
      need(leaf);
      require(
          Arrays.equals(leaf.spkiDer(), slot.spkiDer()),
          "leaf subjectPublicKeyInfo differs from the slot certificate");
      return "leaf SPKI == slot certificate SPKI";
    }

    String chuid() throws Skip {
      byte[] value = request.chuidValue().orElse(null);
      if (value == null) {
        throw new Skip("no CHUID supplied");
      }
      require(f9 != null, "CHUID supplied but no F9 certificate supplied");
      require(opid != null, "CHUID supplied but the F9 OPID is unavailable");
      ChuidIdentityCheck.verify(value, opid);
      return "FASC-N and GUID match OPID " + opid;
    }

    // ---- shared helpers ----

    String signedBy(Cert subject, Cert issuer) throws Exception {
      need(subject);
      need(issuer);
      subject.jdk.verify(issuer.jdk.getPublicKey());
      return "signature verifies under the " + issuer.name + " key";
    }

    String caBasicConstraints(Cert cert, int pathLen) throws Skip, IOException {
      need(cert);
      Extension extension = requireCritical(cert, Extension.basicConstraints, "basicConstraints");
      BasicConstraints bc = BasicConstraints.getInstance(extension.getParsedValue());
      require(bc.isCA(), cert.name + " basicConstraints cA is not TRUE");
      require(
          bc.getPathLenConstraint() != null,
          cert.name + " basicConstraints has no pathLenConstraint (expected " + pathLen + ")");
      require(
          bc.getPathLenConstraint().intValue() == pathLen
              && bc.getPathLenConstraint().bitLength() < 32,
          cert.name
              + " pathLenConstraint is "
              + bc.getPathLenConstraint()
              + ", expected "
              + pathLen);
      return "critical, cA TRUE, pathLen " + pathLen;
    }

    String akiMatches(Cert subject, Cert issuer) throws Skip {
      need(subject);
      need(issuer);
      AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(subject.extensions());
      require(aki != null, subject.name + " has no authorityKeyIdentifier");
      byte[] keyId = aki.getKeyIdentifier();
      require(keyId != null, subject.name + " authorityKeyIdentifier has no keyIdentifier");
      byte[] issuerSki = requireSki(issuer);
      require(
          Arrays.equals(keyId, issuerSki),
          subject.name
              + " authorityKeyIdentifier "
              + hex(keyId)
              + " != "
              + issuer.name
              + " subjectKeyIdentifier "
              + hex(issuerSki));
      return hex(keyId);
    }

    String issuerMatches(Cert subject, Cert issuer) throws Skip, IOException {
      need(subject);
      need(issuer);
      require(
          Arrays.equals(subject.issuerDer(), issuer.subjectDer()),
          subject.name
              + " issuer DER is not byte-identical to the "
              + issuer.name
              + " subject DER");
      return "byte-identical to the " + issuer.name + " subject";
    }

    String validityWithin(Cert inner, Cert outer) throws Skip {
      need(inner);
      need(outer);
      Date notBefore = inner.jdk.getNotBefore();
      Date notAfter = inner.jdk.getNotAfter();
      require(
          !notBefore.before(outer.jdk.getNotBefore()) && !notAfter.after(outer.jdk.getNotAfter()),
          inner.name
              + " validity "
              + notBefore.toInstant()
              + " .. "
              + notAfter.toInstant()
              + " is not within the "
              + outer.name
              + " validity "
              + outer.jdk.getNotBefore().toInstant()
              + " .. "
              + outer.jdk.getNotAfter().toInstant());
      return notBefore.toInstant() + " .. " + notAfter.toInstant();
    }

    void requireLeafExtension() throws Skip {
      need(leaf);
      if (pivLeaf == null) {
        throw new Skip("PIV leaf extension unavailable");
      }
    }

    void need(Cert cert) throws Skip {
      if (cert == null) {
        throw new Skip("certificate not supplied");
      }
      if (cert.bc == null) {
        throw new Skip(cert.name + " certificate failed " + cert.derCheck);
      }
    }
  }

  private static ASN1ObjectIdentifier signatureAlgorithm(Cert cert) {
    AlgorithmIdentifier outer = cert.bc.getSignatureAlgorithm();
    AlgorithmIdentifier inner = cert.bc.getTBSCertificate().getSignature();
    require(
        outer.equals(inner),
        cert.name + " signatureAlgorithm differs from tbsCertificate.signature");
    require(
        outer.getParameters() == null,
        cert.name + " ECDSA signature AlgorithmIdentifier must omit parameters");
    return outer.getAlgorithm();
  }

  private static ASN1ObjectIdentifier ecCurve(Cert cert) {
    AlgorithmIdentifier algorithm = cert.bc.getSubjectPublicKeyInfo().getAlgorithm();
    if (!ID_EC_PUBLIC_KEY.equals(algorithm.getAlgorithm())) {
      return null;
    }
    ASN1Encodable parameters = algorithm.getParameters();
    return parameters instanceof ASN1ObjectIdentifier ? (ASN1ObjectIdentifier) parameters : null;
  }

  private static Extension requireCritical(Cert cert, ASN1ObjectIdentifier oid, String name) {
    Extensions extensions = cert.extensions();
    Extension extension = extensions == null ? null : extensions.getExtension(oid);
    require(extension != null, cert.name + " has no " + name + " extension");
    require(extension.isCritical(), cert.name + " " + name + " must be critical");
    return extension;
  }

  private static byte[] requireSki(Cert cert) throws Skip {
    if (cert.bc == null) {
      throw new Skip(cert.name + " certificate failed " + cert.derCheck);
    }
    SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(cert.extensions());
    require(ski != null, cert.name + " has no subjectKeyIdentifier");
    byte[] value = ski.getKeyIdentifier();
    require(value.length > 0, cert.name + " subjectKeyIdentifier is empty");
    return value;
  }

  private static String singleCommonName(Cert cert) {
    String found = null;
    for (RDN rdn : cert.bc.getSubject().getRDNs()) {
      for (AttributeTypeAndValue attribute : rdn.getTypesAndValues()) {
        if (COMMON_NAME.equals(attribute.getType())) {
          require(found == null, cert.name + " subject has more than one commonName");
          ASN1Encodable value = attribute.getValue();
          require(value instanceof ASN1String, cert.name + " commonName is not a string");
          found = ((ASN1String) value).getString();
        }
      }
    }
    require(found != null, cert.name + " subject has no commonName");
    return found;
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalArgumentException(message);
    }
  }

  private static String hex(byte[] value) {
    return Hex.toHexString(value).toUpperCase(Locale.ROOT);
  }

  private static String describe(Exception e) {
    String message = e.getMessage();
    return message == null || message.isEmpty() ? e.getClass().getSimpleName() : message;
  }
}
