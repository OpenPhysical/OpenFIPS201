package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.makina.security.openfips201.OpenFIPS201;
import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * End-to-end tests for the on-card F9 attestation authority.
 *
 * <p>{@link TestIssuer} stands in for the offline root CA and the Issuer SAM: it verifies the F9
 * proof of possession and issues the F9 certificate in the SAM profile. Every attestation is
 * validated with PKIX from the root through the SAM and F9 certificates to the leaf.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OpenFIPS201AttestationTest extends OpenFIPS201TestSupport {

  private static final boolean FIPS_MODE = Boolean.getBoolean("fips.mode");

  private static final byte ALG_RSA_3072 = (byte) 0x05;
  private static final byte ALG_RSA_1024 = (byte) 0x06;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ALG_ECC_P384 = (byte) 0x14;
  private static final byte SLOT_AUTHENTICATION = (byte) 0x9A;
  private static final byte SLOT_SIGNATURE = (byte) 0x9C;
  private static final byte SLOT_KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte SLOT_CARD_AUTHENTICATION = (byte) 0x9E;
  private static final byte SLOT_RETIRED = (byte) 0x82;
  private static final byte SLOT_RETIRED_SECOND = (byte) 0x83;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;
  private static final byte KEY_REF_ATTESTATION = (byte) 0xF9;
  private static final byte LOCAL_PIN_REFERENCE = (byte) 0x80;
  private static final byte ACCESS_MODE_PIN = (byte) 0x01;
  private static final byte ACCESS_MODE_PIN_ALWAYS = (byte) 0x02;
  private static final byte ACCESS_MODE_VCI = (byte) 0x08;
  private static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F;
  private static final byte ACCESS_MODE_NEVER = (byte) 0x00;
  private static final byte ATTR_NONE = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;
  private static final byte LIFECYCLE_PERSONALIZED = (byte) 0x0F;
  private static final byte STATE_NONE = 0x00;
  private static final byte STATE_GENERATED = 0x01;
  private static final byte STATE_ACTIVATING = 0x02;
  private static final byte STATE_ACTIVE = 0x03;
  private static final byte[] LOCAL_PIN = hex("313233343536FFFF");
  private static final byte[] F9_DEFINITION = hex("6612 8B01F9 8C0100 8D0100 8E0111 8F0104 900100");
  private static final byte[] F9_GENERATE = hex("AC03800111");
  private static final X500Name DEFAULT_TEMPLATE =
      new X500Name("C=US,O=OpenPhysical Test,CN=PIV Attestation Authority");
  private static final String OPENPHYSICAL_ATTESTATION_OID = "1.3.6.1.4.1.57923.20.10.20.1";
  private static final Date VALIDATION_DATE = Date.from(Instant.parse("2030-06-01T00:00:00Z"));
  private static final SecureRandom RANDOM = new SecureRandom();

  @BeforeAll
  static void installProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @BeforeEach
  void requireAttestationBuild() {
    Assumptions.assumeTrue(
        isAttestationEnabledBuild(), "attestation tests require -Dattestation.enabled=true");
  }

  /** Attestation manages its own PIN and F9 authority, so the standard test card is not applied. */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  // ---------------------------------------------------------------------------------------------
  // Positive behaviour
  // ---------------------------------------------------------------------------------------------

  @Test
  void onCardGeneratedAuthorityChainsToRoot() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());

    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority, issuer);
  }

  @Test
  void authorityCertificateLoadsThroughUpdateKey() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final byte[] certificate = issuer.sign(issuer.profile(point, opid(), DEFAULT_TEMPLATE));
    ResponseAPDU response =
        withMockedScp(
            () ->
                transmitChained(
                    0x84,
                    0x25,
                    0x01,
                    KEY_REF_ATTESTATION & 0xFF,
                    concat(
                        new byte[] {(byte) 0x80, 0x01, ALG_ECC_P256},
                        tlv((byte) 0x30, tlv((byte) 0x70, certificate)))));
    assertSw(ISO7816.SW_NO_ERROR, response, "UPDATE KEY must load the F9 certificate");
    assertEquals(STATE_ACTIVE, authorityState());
  }

  @Test
  void f9CertificateServedByAttestF9MatchesLoaded() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());

    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 certificate read-back");
    byte[] served =
        collectResponse(
            transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 256)),
            "00 F9 F9 00 must return the F9 certificate");
    assertArrayEquals(authority.certificateDer, served);

    byte[] container =
        collectResponse(
            transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FFF01"), 256),
            "GET DATA 5FFF01 must return the F9 certificate container");
    assertArrayEquals(
        concat(
            tlv(
                (byte) 0x53,
                concat(tlv((byte) 0x70, authority.certificateDer), hex("710100FE00")))),
        container);

    // The virtual object is read-only and cannot be shadowed by a stored object.
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before 5FFF01 create attempt");
          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("640F8B035FFF018C017F8D017F9202 0100")),
              "CREATE OBJECT 5FFF01 must be refused");
        });
  }

  @Test
  void generatedAuthorityIsGeneratedOrigin() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());

    // The certified key is exactly the point returned by on-card generation, and possession was
    // proven with that key before certification.
    ECPublicKey certified = (ECPublicKey) authority.certificate.getPublicKey();
    assertArrayEquals(authority.point, encodePoint(certified, 32));
    assertTrue(authority.proofVerified, "F9 proof of possession must verify");
    assertEquals(
        authority.ski.length,
        20,
        "F9 SKI is the RFC 7093 method 1 identifier over the generated point");
    assertArrayEquals(rfc7093KeyId(authority.point), authority.ski);
  }

  @Test
  void leafKeyUsageMatchesRole() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());

    assertLeafKeyUsage(authority, issuer, SLOT_AUTHENTICATION, ALG_ECC_P256, "AC03800111", 0);
    assertLeafKeyUsage(
        authority, issuer, SLOT_SIGNATURE, signatureAlgorithm(), signatureGenerateRequest(), 0);
    assertLeafKeyUsage(authority, issuer, SLOT_CARD_AUTHENTICATION, ALG_ECC_P256, "AC03800111", 0);
    assertLeafKeyUsage(authority, issuer, SLOT_KEY_MANAGEMENT, ALG_ECC_P256, "AC03800111", 4);
    assertLeafKeyUsage(authority, issuer, SLOT_RETIRED, ALG_RSA_2048, "AC03800107", 2);
  }

  @Test
  void leafCarriesAuthorityKeyIdentifier() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    X509Certificate leaf = attest(SLOT_AUTHENTICATION);

    assertFalse(
        leaf.getCriticalExtensionOIDs().contains(Extension.authorityKeyIdentifier.getId()),
        "AKI must be non-critical");
    byte[] aki = leaf.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    assertNotNull(aki, "Leaf must carry an AKI");
    AuthorityKeyIdentifier parsed =
        AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(aki).getOctets());
    assertArrayEquals(authority.ski, parsed.getKeyIdentifier());
    assertArrayEquals(
        authority.certificate.getSubjectX500Principal().getEncoded(),
        leaf.getIssuerX500Principal().getEncoded());
  }

  @Test
  void leafOpenPhysicalExtensionReflectsBuildAndPolicy() throws Exception {
    assertArrayEquals(
        hex("060C2B0601040183C443140A1401"),
        new ASN1ObjectIdentifier(OPENPHYSICAL_ATTESTATION_OID).getEncoded(),
        "Applet OID encoding must match BouncyCastle");

    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    X509Certificate leaf = attest(SLOT_AUTHENTICATION);
    assertValidAttestation(leaf, authority, issuer);

    assertFalse(leaf.getCriticalExtensionOIDs().contains(OPENPHYSICAL_ATTESTATION_OID));
    byte[] wrapped = leaf.getExtensionValue(OPENPHYSICAL_ATTESTATION_OID);
    assertNotNull(wrapped, "Leaf must carry the OpenPhysical attestation extension");
    ASN1Sequence body = ASN1Sequence.getInstance(ASN1OctetString.getInstance(wrapped).getOctets());
    assertEquals(12, body.size());
    assertEquals(BigInteger.ONE, ASN1Integer.getInstance(body.getObjectAt(0)).getValue());
    assertArrayEquals(new byte[] {1, 11, 0, 0}, octets(body, 1), "appletVersion 1.11.0");
    assertArrayEquals(new byte[] {(byte) ((FIPS_MODE ? 1 : 0) | 2)}, octets(body, 2));
    assertArrayEquals(new byte[] {isCs7Build() ? (byte) 0x2E : (byte) 0x27}, octets(body, 3));
    assertArrayEquals(
        capPlatformId().getBytes(StandardCharsets.US_ASCII),
        octets(body, 4),
        "platformId must match the CAP build descriptor");
    assertArrayEquals(new byte[] {SLOT_AUTHENTICATION}, octets(body, 5));
    assertArrayEquals(new byte[] {ALG_ECC_P256}, octets(body, 6));
    assertArrayEquals(new byte[] {0x04}, octets(body, 7));
    assertArrayEquals(new byte[] {ATTR_NONE}, octets(body, 8));
    assertEquals(BigInteger.valueOf(2), ASN1Enumerated.getInstance(body.getObjectAt(9)).getValue());
    assertArrayEquals(new byte[] {ACCESS_MODE_PIN}, octets(body, 10));
    assertArrayEquals(new byte[] {(byte) (ACCESS_MODE_VCI | ACCESS_MODE_PIN)}, octets(body, 11));
  }

  @Test
  void leafIsCanonicalDer() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());

    assertCanonicalLeaf(authority, issuer, SLOT_AUTHENTICATION, ALG_ECC_P256, "AC03800111");
    assertCanonicalLeaf(authority, issuer, SLOT_CARD_AUTHENTICATION, ALG_ECC_P384, "AC03800114");
    assertCanonicalLeaf(authority, issuer, SLOT_RETIRED, ALG_RSA_2048, "AC03800107");
    assertCanonicalLeaf(authority, issuer, SLOT_RETIRED_SECOND, ALG_RSA_3072, "AC03800105");
  }

  @Test
  void attestationHandlesMaximumIssuerProfileWithRsa3072Target() throws Exception {
    // The largest supported issuer subject (0x80 octets including the 17-digit OPID) together with
    // the largest supported target SPKI must fit the 1024-octet response buffer.
    TestIssuer issuer = TestIssuer.create();
    String opid = opid();
    X500Name template = new X500Name("C=US,O=" + repeated('O', 32) + ",CN=" + repeated('C', 31));
    byte[] subject = subjectWithOpid(template, opid);
    assertEquals(0x80, subject.length, "fixture must sit at the subject maximum");

    Authority authority = provisionAuthorityOverScp(issuer, template, opid);
    createAsymmetricKeyOverScp(SLOT_KEY_MANAGEMENT, ALG_RSA_3072);
    generateKeyOverScp(SLOT_KEY_MANAGEMENT, "AC03800105");
    assertValidAttestation(attest(SLOT_KEY_MANAGEMENT), authority, issuer);
  }

  @Test
  void attestationCertificateMatchesDocumentedProfile() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    X509Certificate cert = attest(SLOT_AUTHENTICATION);

    assertEquals(3, cert.getVersion());
    assertEquals(authority.certificate.getNotBefore(), cert.getNotBefore());
    assertEquals(authority.certificate.getNotAfter(), cert.getNotAfter());
    assertEquals(
        new javax.security.auth.x500.X500Principal("CN=PIV Attestation 9A"),
        cert.getSubjectX500Principal(),
        "Subject must name the attested slot");
    assertEquals(-1, cert.getBasicConstraints(), "BasicConstraints must assert CA=false");
    assertFalse(cert.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));
    assertTrue(cert.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
    boolean[] keyUsage = cert.getKeyUsage();
    assertTrue(keyUsage != null && keyUsage[0], "KeyUsage must assert digitalSignature");
    for (int i = 1; i < keyUsage.length; i++) {
      assertFalse(keyUsage[i], "KeyUsage must assert only digitalSignature");
    }
    assertEquals("1.2.840.10045.4.3.2", cert.getSigAlgOID());
    assertEquals(1, cert.getSerialNumber().signum(), "Serial must be positive");
    assertTrue(cert.getSerialNumber().bitLength() <= 127, "Serial must fit 16 octets");
    assertEquals(
        new java.util.HashSet<String>(
            Arrays.asList(
                Extension.basicConstraints.getId(),
                Extension.keyUsage.getId(),
                Extension.authorityKeyIdentifier.getId(),
                OPENPHYSICAL_ATTESTATION_OID)),
        allExtensionOids(cert));
  }

  @Test
  void multipleAttestationsInOneSessionShareTheResponseBuffer() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    createAsymmetricKeyOverScp(SLOT_SIGNATURE, signatureAlgorithm());
    generateKeyOverScp(SLOT_SIGNATURE, signatureGenerateRequest());

    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority, issuer);
    assertValidAttestation(attest(SLOT_SIGNATURE), authority, issuer);
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority, issuer);
    assertValidAttestation(attest(SLOT_SIGNATURE), authority, issuer);
  }

  @Test
  void rsaAttestationCertificateContainsGeneratedPublicKey() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_KEY_MANAGEMENT, ALG_RSA_2048);
    byte[] generatedPublicKey = generateKeyOverScp(SLOT_KEY_MANAGEMENT, "AC03800107");

    RSAPublicKey attestedPublicKey = (RSAPublicKey) attest(SLOT_KEY_MANAGEMENT).getPublicKey();
    assertEquals(
        new BigInteger(1, tlvValue(generatedPublicKey, (byte) 0x81)),
        attestedPublicKey.getModulus());
    assertEquals(
        new BigInteger(1, tlvValue(generatedPublicKey, (byte) 0x82)),
        attestedPublicKey.getPublicExponent());
  }

  @Test
  void compatibilityRsa1024TargetIsSignedByAuthority() throws Exception {
    Assumptions.assumeFalse(FIPS_MODE, "The FIPS profile omits RSA-1024");
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_RETIRED, ALG_RSA_1024);
    generateKeyOverScp(SLOT_RETIRED, "AC03800106");
    X509Certificate leaf = attest(SLOT_RETIRED);
    leaf.verify(authority.certificate.getPublicKey());
  }

  @Test
  void getStatusReportsAuthorityStateAndOpid() throws Exception {
    assertEquals(STATE_NONE, statusValue((byte) 0x89)[0]);
    assertStatusLacks((byte) 0x8A);

    TestIssuer issuer = TestIssuer.create();
    byte[] point = defineAndGenerateAuthority();
    assertEquals(STATE_GENERATED, statusValue((byte) 0x89)[0]);
    assertStatusLacks((byte) 0x8A);
    assertStatusLacks((byte) 0x8B);

    String opid = opid();
    loadCertificateOk(issuer.sign(issuer.profile(point, opid, DEFAULT_TEMPLATE)));
    assertEquals(STATE_ACTIVE, statusValue((byte) 0x89)[0]);
    assertArrayEquals(opid.getBytes(StandardCharsets.US_ASCII), statusValue((byte) 0x8A));
    assertArrayEquals(rfc7093KeyId(point), statusValue((byte) 0x8B));
  }

  @Test
  void activationClearsExistingKeyMaterialAndDataObjectContents() throws Exception {
    createDataObjectOverScp((byte) 0x02);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());

    ResponseAPDU cleared = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC102"));
    assertSw(ISO7816.SW_NO_ERROR, cleared, "Activation should clear data object contents");
    assertArrayEquals(hex("5300"), cleared.getData());
    verifyLocalPin();
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "Keys generated before activation are wiped and must be regenerated");
  }

  @Test
  void selectionResumesInterruptedActivation() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createDataObjectOverScp((byte) 0x02);

    // Model a tear after the certificate commit (state ACTIVATING) and before the wipe finished.
    setAuthorityState(STATE_ACTIVATING);
    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT resumes the activation wipe");

    ResponseAPDU cleared = transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC102"));
    assertSw(ISO7816.SW_NO_ERROR, cleared, "GET DATA after resumed activation");
    assertArrayEquals(hex("5300"), cleared.getData());
    assertEquals(STATE_ACTIVE, authorityState());
  }

  // ---------------------------------------------------------------------------------------------
  // F9 definition, generation and proof of possession
  // ---------------------------------------------------------------------------------------------

  @Test
  void f9KeyDefinitionRequiresAttrNone() {
    assertF9DefinitionRejected(
        ACCESS_MODE_ALWAYS, ACCESS_MODE_NEVER, ALG_ECC_P256, (byte) 0x04, ATTR_NONE, "contact");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER, ACCESS_MODE_ALWAYS, ALG_ECC_P256, (byte) 0x04, ATTR_NONE, "contactless");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER, ACCESS_MODE_NEVER, ALG_ECC_P384, (byte) 0x04, ATTR_NONE, "mechanism");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER, ACCESS_MODE_NEVER, ALG_ECC_P256, (byte) 0x01, ATTR_NONE, "role");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER,
        ACCESS_MODE_NEVER,
        ALG_ECC_P256,
        (byte) 0x04,
        ATTR_IMPORTABLE,
        "importable attribute");
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 definition");
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION),
              "Non-importable F9 definition");
        });
  }

  @Test
  void generateAuthorityRequiresSecureChannel() {
    defineAuthority();
    provisionManagementKeyOverScp(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(0x80, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
        "9B authentication alone must not generate F9");
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        transmit(0x00, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
        "SP 800-73-5 interindustry GENERATE does not address F9");
  }

  @Test
  void generateAuthorityStatusWords() {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before undefined F9 generate");
          assertSw(
              ISO7816.SW_INCORRECT_P1P2,
              transmit(0x84, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
              "F9 not defined");
          assertSw(ISO7816.SW_NO_ERROR, transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION), "F9");
          // SP 800-73-5 Part 2 Section 3.3.2: '6A 86' when "the cryptographic mechanism of the
          // reference data to be generated is different than the cryptographic mechanism of the
          // reference data of a given key reference".
          assertSw(
              ISO7816.SW_INCORRECT_P1P2,
              transmit(0x84, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, hex("AC03800114")),
              "F9 mechanism must be P-256");
        });
    withMockedScp(
        LIFECYCLE_PERSONALIZED,
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PERSONALIZED generate");
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              transmit(0x84, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
              "F9 cannot be generated once PERSONALIZED");
          return null;
        });
    // Regeneration before a certificate is accepted is allowed and keeps the authority GENERATED.
    byte[] first = generateAuthority();
    byte[] second = generateAuthority();
    assertFalse(Arrays.equals(first, second), "Regeneration must replace the F9 pair");
    assertEquals(STATE_GENERATED, authorityState());
  }

  @Test
  void generateAuthorityIsRefusedAfterActivation() throws Exception {
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 regeneration");
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              transmit(0x84, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
              "F9 is immutable once ACTIVE");
          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("67068B01F98E0111")),
              "F9 cannot be deleted");
        });
  }

  @Test
  void proveAuthorityStatusWords() throws Exception {
    final byte[] nonce = randomBytes(32);
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PROVE checks");
          assertSw(0x6A88, prove(nonce), "PROVE with F9 undefined");
          assertSw(ISO7816.SW_NO_ERROR, transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION), "F9");
          assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, prove(nonce), "PROVE before GENERATE");
          assertSw(ISO7816.SW_WRONG_LENGTH, prove(new byte[15]), "15-octet nonce");
          assertSw(ISO7816.SW_WRONG_LENGTH, prove(new byte[65]), "65-octet nonce");
          assertSw(
              ISO7816.SW_INCORRECT_P1P2,
              transmit(0x84, 0xF9, 0xF9, 0x02, nonce),
              "PROVE requires P2=01");
        });
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        transmit(0x80, 0xF9, 0xF9, 0x01, nonce),
        "PROVE requires SCP");

    byte[] point = generateAuthority();
    for (int length : new int[] {16, 32, 64}) {
      final byte[] n = randomBytes(length);
      byte[] signature =
          withMockedScp(
              () -> {
                assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PROVE");
                return collectResponse(prove(n), "PROVE with a " + n.length + "-octet nonce");
              });
      assertTrue(verifyPop(signature, n, point), "PoP must verify for " + length + " octets");
    }
  }

  @Test
  void proveAuthorityIsRefusedAfterActivationAndWhenPersonalized() throws Exception {
    final byte[] point = defineAndGenerateAuthority();
    withMockedScp(
        LIFECYCLE_PERSONALIZED,
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PERSONALIZED PROVE");
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              prove(randomBytes(32)),
              "PROVE refused once PERSONALIZED");
          return null;
        });
    TestIssuer issuer = TestIssuer.create();
    loadCertificateOk(issuer.sign(issuer.profile(point, opid(), DEFAULT_TEMPLATE)));
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before PROVE after activation");
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              prove(randomBytes(32)),
              "PROVE is permanently disabled once ACTIVE");
        });
  }

  // ---------------------------------------------------------------------------------------------
  // Authority element provisioning
  // ---------------------------------------------------------------------------------------------

  @Test
  void authorityElementsBeforeActivation() throws Exception {
    final byte[] point = defineAndGenerateAuthority();
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 element checks");
          assertSw(
              ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
              crdF9((byte) 0x86, point),
              "F9 public key import is not permitted");
          assertSw(
              ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
              crdF9((byte) 0x87, new byte[32]),
              "F9 private key import is not permitted");
          assertSw(ISO7816.SW_WRONG_DATA, crdF9((byte) 0x92, new byte[4]), "92 is obsolete");
          assertSw(ISO7816.SW_WRONG_DATA, crdF9((byte) 0x93, new byte[4]), "93 is obsolete");
          assertSw(ISO7816.SW_WRONG_DATA, crdF9((byte) 0xE0, new byte[0]), "E0 is refused");
        });
    assertEquals(STATE_GENERATED, authorityState(), "Rejected elements leave F9 GENERATED");
  }

  @Test
  void authorityCertificateRequiresSecureChannel() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    byte[] point = defineAndGenerateAuthority();
    byte[] certificate = issuer.sign(issuer.profile(point, opid(), DEFAULT_TEMPLATE));
    provisionManagementKeyOverScp(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    authenticateCardManagementKey(StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    ResponseAPDU response =
        transmitChained(
            0x80,
            0x25,
            0x01,
            KEY_REF_ATTESTATION & 0xFF,
            concat(
                new byte[] {(byte) 0x80, 0x01, ALG_ECC_P256},
                tlv((byte) 0x30, tlv((byte) 0x70, certificate))));
    assertSw(
        ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED,
        response,
        "9B authentication alone must not load the F9 certificate");
  }

  @Test
  void authorityCertificateRequiresGeneratedAuthority() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    KeyPair foreign = generateEc(32);
    final byte[] certificate =
        issuer.sign(
            issuer.profile(
                encodePoint((ECPublicKey) foreign.getPublic(), 32), opid(), DEFAULT_TEMPLATE));
    defineAuthority();
    ResponseAPDU response = withMockedScp(() -> loadCertificate(certificate));
    assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response, "Load before GENERATE");
  }

  @Test
  void reprovisioningIsRefusedAfterActivation() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before re-provisioning");
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              loadCertificate(authority.certificateDer),
              "70 after activation");
          for (byte tag : new byte[] {(byte) 0x86, (byte) 0x87, (byte) 0x92, (byte) 0x93}) {
            assertSw(
                ISO7816.SW_CONDITIONS_NOT_SATISFIED,
                crdF9(tag, new byte[32]),
                String.format("%02X after activation", tag));
          }
          assertSw(
              ISO7816.SW_CONDITIONS_NOT_SATISFIED,
              crdF9((byte) 0xE0, new byte[0]),
              "E0 after activation");
        });
    assertEquals(STATE_ACTIVE, authorityState());
  }

  @Test
  void certificateBindingIsEnforced() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final String opid = opid();

    KeyPair foreign = generateEc(32);
    F9Profile foreignKey =
        issuer.profile(encodePoint((ECPublicKey) foreign.getPublic(), 32), opid, DEFAULT_TEMPLATE);
    foreignKey.extensions.put("ski", extension(Extension.subjectKeyIdentifier, false, ski(point)));
    assertLoadRejected(issuer, foreignKey, ISO7816.SW_WRONG_DATA, "foreign SPKI");

    F9Profile wrongSki = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    byte[] other = rfc7093KeyId(point);
    other[0] ^= 0x01;
    wrongSki.extensions.put(
        "ski", extension(Extension.subjectKeyIdentifier, false, tlv((byte) 0x04, other)));
    assertLoadRejected(issuer, wrongSki, ISO7816.SW_WRONG_DATA, "wrong SKI");

    F9Profile sha1Ski = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    sha1Ski.extensions.put(
        "ski",
        extension(
            Extension.subjectKeyIdentifier,
            false,
            tlv((byte) 0x04, Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(point), 20))));
    assertLoadRejected(issuer, sha1Ski, ISO7816.SW_WRONG_DATA, "RFC 5280 SHA-1 SKI");

    F9Profile missingSki = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    missingSki.extensions.remove("ski");
    assertLoadRejected(issuer, missingSki, ISO7816.SW_WRONG_DATA, "missing SKI");

    F9Profile missingAki = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    missingAki.extensions.remove("aki");
    assertLoadRejected(issuer, missingAki, ISO7816.SW_WRONG_DATA, "missing AKI");

    assertEquals(STATE_GENERATED, authorityState(), "Rejected certificates leave F9 GENERATED");
    loadCertificateOk(issuer.sign(issuer.profile(point, opid, DEFAULT_TEMPLATE)));
  }

  @Test
  void certificateConstraintsAreEnforced() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final String opid = opid();

    assertExtensionRejected(
        issuer, point, opid, "bc", extension(Extension.basicConstraints, true, hex("3000")), "CA");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "bc",
        extension(Extension.basicConstraints, true, hex("30060101FF020101")),
        "pathLen 1");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "bc",
        extension(Extension.basicConstraints, true, hex("30030101FF")),
        "no pathLen");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "bc",
        extension(Extension.basicConstraints, false, hex("30060101FF020100")),
        "BC non-critical");
    assertExtensionRejected(
        issuer, point, opid, "ku", extension(Extension.keyUsage, true, hex("03020780")), "KU");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "ku",
        extension(Extension.keyUsage, true, hex("03020186")),
        "KU keyCertSign with extra bits");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "ku",
        extension(Extension.keyUsage, false, hex("03020204")),
        "KU non-critical");
    assertExtensionRejected(
        issuer,
        point,
        opid,
        "unknown",
        extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.99.1"), true, hex("0500")),
        "unknown critical extension");

    F9Profile duplicate = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    duplicate.extensions.put("ku2", duplicate.extensions.get("ku"));
    assertLoadRejected(issuer, duplicate, ISO7816.SW_WRONG_DATA, "duplicate KU");

    F9Profile v1 = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    v1.version = new byte[0];
    v1.extensions.clear();
    assertLoadRejected(issuer, v1, ISO7816.SW_WRONG_DATA, "v1 certificate");

    F9Profile v2 = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    v2.version = hex("A003020101");
    assertLoadRejected(issuer, v2, ISO7816.SW_WRONG_DATA, "v2 certificate");

    F9Profile mismatched = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    mismatched.tbsAlgorithm = hex("300A06082A8648CE3D040303");
    assertLoadRejected(issuer, mismatched, ISO7816.SW_WRONG_DATA, "mismatched signature algs");

    // Both AlgorithmIdentifiers must be exactly ecdsa-with-SHA256 with absent parameters.
    String[][] algorithms = {
      {"300A06082A8648CE3D040303", "ecdsa-with-SHA384"},
      {"300D06092A864886F70D01010B0500", "sha256WithRSAEncryption"},
      {"300C06082A8648CE3D0403020500", "ecdsa-with-SHA256 with parameters"}
    };
    for (String[] algorithm : algorithms) {
      F9Profile other = issuer.profile(point, opid, DEFAULT_TEMPLATE);
      other.tbsAlgorithm = hex(algorithm[0]);
      other.signatureAlgorithm = hex(algorithm[0]);
      assertLoadRejected(issuer, other, ISO7816.SW_WRONG_DATA, algorithm[1]);
    }

    F9Profile selfIssued = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    selfIssued.issuer = selfIssued.subject;
    assertLoadRejected(issuer, selfIssued, ISO7816.SW_WRONG_DATA, "self-issued certificate");

    F9Profile uniqueId = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    uniqueId.beforeExtensions = hex("81020000");
    assertLoadRejected(issuer, uniqueId, ISO7816.SW_WRONG_DATA, "issuerUniqueID");

    F9Profile noExtensions = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    noExtensions.extensions.clear();
    assertLoadRejected(issuer, noExtensions, ISO7816.SW_WRONG_DATA, "no extensions");

    loadCertificateOk(issuer.sign(issuer.profile(point, opid, DEFAULT_TEMPLATE)));
  }

  @Test
  void certificateOpidIsEnforced() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final String opid = opid();
    // A short template keeps every malformed subject below the 0x80 subject limit.
    final X500Name template = new X500Name("C=US,CN=Card");

    assertSubjectRejected(issuer, point, template.getEncoded(), "missing OPID");
    assertSubjectRejected(
        issuer, point, subject(template, serialNumber(opid), serialNumber(opid)), "duplicate OPID");
    assertSubjectRejected(
        issuer,
        point,
        subject(
            template,
            new RDN(
                new AttributeTypeAndValue[] {
                  new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Card")),
                  new AttributeTypeAndValue(BCStyle.SERIALNUMBER, new DERPrintableString(opid))
                })),
        "multi-valued RDN");
    assertSubjectRejected(
        issuer,
        point,
        subject(
            template,
            new RDN(new AttributeTypeAndValue(BCStyle.SERIALNUMBER, new DERUTF8String(opid)))),
        "UTF8String OPID");
    String badLuhn =
        opid.substring(0, opid.length() - 1)
            + (char) ('0' + ((opid.charAt(opid.length() - 1) - '0' + 1) % 10));
    assertSubjectRejected(issuer, point, subjectWithOpid(template, badLuhn), "bad Luhn");
    // Only the 17-digit layout is valid: 16 and 18 digits with a valid Luhn digit are rejected,
    // as are the retired format-coded OPIDs (for example the 18-digit format 0 and 11-digit
    // format 2 forms).
    assertSubjectRejected(
        issuer, point, subjectWithOpid(template, withCheckDigit("123412345678901")), "16 digits");
    assertSubjectRejected(
        issuer, point, subjectWithOpid(template, withCheckDigit("12341234567890123")), "18 digits");
    assertSubjectRejected(
        issuer,
        point,
        subjectWithOpid(template, withCheckDigit("12340123412345678")),
        "retired format 0 OPID");
    assertSubjectRejected(
        issuer, point, subjectWithOpid(template, withCheckDigit("1234212345")), "format 2 OPID");
    String nonDigit = opid.substring(0, 6) + "A" + opid.substring(7);
    assertSubjectRejected(issuer, point, subjectWithOpid(template, nonDigit), "letters");

    loadCertificateOk(issuer.sign(issuer.profile(point, opid, template)));
  }

  @Test
  void certificateEncodingMustBeCanonicalDer() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final String opid = opid();

    F9Profile longForm = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    longForm.extensions.put(
        "ski",
        tlv(
            (byte) 0x30,
            concat(
                tlv((byte) 0x06, hex("551D0E")),
                concat(hex("048116"), tlv((byte) 0x04, rfc7093KeyId(point))))));
    assertLoadRejected(issuer, longForm, ISO7816.SW_WRONG_DATA, "long-form short length");

    F9Profile explicitFalse = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    explicitFalse.extensions.put(
        "aki",
        tlv(
            (byte) 0x30,
            concat(
                tlv((byte) 0x06, hex("551D23")),
                hex("010100"),
                tlv((byte) 0x04, issuer.authorityKeyIdentifier()))));
    assertLoadRejected(issuer, explicitFalse, ISO7816.SW_WRONG_DATA, "explicit FALSE critical");

    F9Profile trailing = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    trailing.trailing = new byte[] {0x00};
    assertLoadRejected(issuer, trailing, ISO7816.SW_WRONG_DATA, "trailing octet");

    F9Profile redundantSerial = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    byte[] serial = randomBytes(16);
    serial[0] &= 0x3F;
    redundantSerial.serial = tlv((byte) 0x02, concat(new byte[] {0x00}, serial));
    assertLoadRejected(issuer, redundantSerial, ISO7816.SW_WRONG_DATA, "serial with redundant 00");

    F9Profile negativeSerial = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    negativeSerial.serial = hex("0201FF");
    assertLoadRejected(issuer, negativeSerial, ISO7816.SW_WRONG_DATA, "negative serial");

    F9Profile zeroSerial = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    zeroSerial.serial = hex("020100");
    assertLoadRejected(issuer, zeroSerial, ISO7816.SW_WRONG_DATA, "zero serial");

    F9Profile longSerial = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    longSerial.serial = tlv((byte) 0x02, concat(new byte[] {0x01}, new byte[20]));
    assertLoadRejected(issuer, longSerial, ISO7816.SW_WRONG_DATA, "21-octet serial");

    loadCertificateOk(issuer.sign(issuer.profile(point, opid, DEFAULT_TEMPLATE)));
  }

  @Test
  void oversizeCertificateAndSubjectAreRejected() throws Exception {
    final TestIssuer issuer = TestIssuer.create();
    final byte[] point = defineAndGenerateAuthority();
    final String opid = opid();

    // Pad with a non-critical extension until the certificate sits just above 0x2E0 octets; the
    // signature length varies by a few octets between signings.
    F9Profile padded = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    ASN1ObjectIdentifier paddingOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.99.2");
    int padding = 0x2E8 - issuer.sign(padded).length - 20;
    for (int attempt = 0; attempt < 4; attempt++) {
      padded.extensions.put(
          "padding", extension(paddingOid, false, tlv((byte) 0x04, new byte[padding])));
      padding += 0x2E8 - issuer.sign(padded).length;
    }
    padded.extensions.put(
        "padding", extension(paddingOid, false, tlv((byte) 0x04, new byte[padding])));
    int oversize = issuer.sign(padded).length;
    assertTrue(oversize > 0x2E2 && oversize < 0x2F0, "fixture size " + oversize);
    assertLoadRejected(issuer, padded, ISO7816.SW_FILE_FULL, "oversize certificate");

    X500Name large = new X500Name("C=US,O=" + repeated('O', 32) + ",CN=" + repeated('C', 32));
    F9Profile largeSubject = issuer.profile(point, opid(), large);
    assertEquals(0x81, largeSubject.subject.length, "fixture must exceed the subject maximum");
    assertLoadRejected(issuer, largeSubject, ISO7816.SW_FILE_FULL, "oversize subject");

    loadCertificateOk(issuer.sign(issuer.profile(point, opid, DEFAULT_TEMPLATE)));
  }

  // ---------------------------------------------------------------------------------------------
  // Leaf issuance rules
  // ---------------------------------------------------------------------------------------------

  @Test
  void attestBeforeAuthorityProvisionedFails() {
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "Attestation before activation must return 6985");
  }

  @Test
  void attestRejectsUnattestableSlots() {
    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before slot validation checks");
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 0)),
        "00 F9 F9 00 without an active authority");
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        transmit(new CommandAPDU(0x00, 0xF9, KEY_REF_CARD_MANAGEMENT & 0xFF, 0x00, 0)),
        "INS F9 must reject the management key slot");
    assertSw(
        ISO7816.SW_FILE_NOT_FOUND,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FFF01")),
        "5FFF01 does not exist before activation");
  }

  @Test
  void attestNonExistentSlotFails() throws Exception {
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    assertSw(
        0x6A88,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "Attestation of non-existent slot key must return 6A88");
  }

  @Test
  void attestEnforcesRetiredSlotRangeBoundaries() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        transmit(new CommandAPDU(0x00, 0xF9, 0x81, 0x00, 0)),
        "Slot 81 sits below the retired-slot range");
    assertSw(
        ISO7816.SW_INCORRECT_P1P2,
        transmit(new CommandAPDU(0x00, 0xF9, 0x96, 0x00, 0)),
        "Slot 96 sits above the retired-slot range");

    createAsymmetricKeyOverScp((byte) 0x95, ALG_ECC_P256);
    generateKeyOverScp((byte) 0x95, "AC03800111");
    assertValidAttestation(attest((byte) 0x95), authority, issuer);
  }

  @Test
  void administrativeDeleteRemovesGeneratedAttestationTarget() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_RETIRED, ALG_ECC_P256);
    generateKeyOverScp(SLOT_RETIRED, "AC03800111");
    assertValidAttestation(attest(SLOT_RETIRED), authority, issuer);

    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before delete-key");
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmit(0x84, 0xDB, 0xFF, 0xFF, hex("67068B01828E0111")),
              "Administrative delete-key should remove retired slot 82");
        });
    assertSw(
        0x6A88,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_RETIRED & 0xFF, 0x00, 0)),
        "Deleted key must no longer be attestable");
  }

  @Test
  void createdButNotGeneratedKeyIsNotAttestable() throws Exception {
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    verifyLocalPin();
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "A key definition without generated material must not be attestable");
  }

  @Test
  void importedTargetKeysAreNotAttestable() throws Exception {
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    // 9D and retired references stay importable in every profile.
    assertImportedEccTargetIsNotAttestable(SLOT_KEY_MANAGEMENT, ALG_ECC_P256, 32);
    assertImportedEccTargetIsNotAttestable(SLOT_CARD_AUTHENTICATION, ALG_ECC_P256, 32);
    if (!FIPS_MODE) {
      assertImportedEccTargetIsNotAttestable(SLOT_AUTHENTICATION, ALG_ECC_P256, 32);
    }
  }

  @Test
  void generatedKeyLosesAttestabilityAfterKeyImport() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(SLOT_KEY_MANAGEMENT, ALG_ECC_P256, ATTR_IMPORTABLE);
    generateKeyOverScp(SLOT_KEY_MANAGEMENT, "AC03800111");
    assertValidAttestation(attest(SLOT_KEY_MANAGEMENT), authority, issuer);

    KeyPair replacement = generateEc(32);
    importKeyElementOverScp(ALG_ECC_P256, SLOT_KEY_MANAGEMENT, (byte) 0xE0, new byte[0]);
    importKeyElementOverScp(
        ALG_ECC_P256,
        SLOT_KEY_MANAGEMENT,
        (byte) 0x86,
        encodePoint((ECPublicKey) replacement.getPublic(), 32));
    importKeyElementOverScp(
        ALG_ECC_P256,
        SLOT_KEY_MANAGEMENT,
        (byte) 0x87,
        fixed(((java.security.interfaces.ECPrivateKey) replacement.getPrivate()).getS(), 32));

    verifyLocalPin();
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_KEY_MANAGEMENT & 0xFF, 0x00, 0)),
        "A generated key overwritten by import must not be attestable");
  }

  @Test
  void attestationRequiresTargetSlotPinWhenTargetAclRequiresPin() throws Exception {
    TestIssuer issuer = TestIssuer.create();
    Authority authority = provisionAuthorityOverScp(issuer, DEFAULT_TEMPLATE, opid());
    setLocalPinOverScp(LOCAL_PIN);
    // Table 5 access modes: PIN on contact, VCI+PIN on contactless. Valid in every profile.
    createAsymmetricKeyOverScp(
        SLOT_AUTHENTICATION,
        ALG_ECC_P256,
        ACCESS_MODE_PIN,
        (byte) (ACCESS_MODE_VCI | ACCESS_MODE_PIN),
        ATTR_NONE);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before ACL check");
    assertSw(
        0x6982,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "INS F9 must honor the target key access mode");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority, issuer);
  }

  @Test
  void attestationHonorsTargetContactlessAccessModeStandardProfile() throws Exception {
    Assumptions.assumeFalse(FIPS_MODE, "FIPS fixes the 9A contactless mode to VCI and PIN");
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    createAsymmetricKeyOverScp(
        SLOT_AUTHENTICATION, ALG_ECC_P256, ACCESS_MODE_ALWAYS, ACCESS_MODE_NEVER, ATTR_NONE);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertContactlessAttestationBlocked(SLOT_AUTHENTICATION);
  }

  @Test
  void attestationHonorsTargetContactlessAccessModeFipsProfile() throws Exception {
    Assumptions.assumeTrue(FIPS_MODE, "FIPS Table 5 contactless access modes");
    provisionAuthorityOverScp(TestIssuer.create(), DEFAULT_TEMPLATE, opid());
    // 9A requires VCI and PIN over contactless; without VCI the target ACL blocks attestation.
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertContactlessAttestationBlocked(SLOT_AUTHENTICATION);
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: authority provisioning
  // ---------------------------------------------------------------------------------------------

  /** Defines F9 (non-importable), generates it, proves possession, certifies and loads it. */
  private Authority provisionAuthorityOverScp(
      final TestIssuer issuer, final X500Name template, final String opid) throws Exception {
    final byte[] point = defineAndGenerateAuthority();
    final byte[] nonce = randomBytes(32);
    byte[] proof =
        withMockedScp(
            () -> {
              assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 PROVE");
              return collectResponse(prove(nonce), "F9 PROVE");
            });
    boolean proofVerified = verifyPop(proof, nonce, point);
    assertTrue(proofVerified, "F9 proof of possession must verify before certification");

    byte[] certificate = issuer.sign(issuer.profile(point, opid, template));
    loadCertificateOk(certificate);
    assertEquals(STATE_ACTIVE, authorityState());
    X509Certificate parsed = parseCertificate(certificate);
    return new Authority(point, certificate, parsed, rfc7093KeyId(point), proofVerified);
  }

  private void defineAuthority() {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 definition");
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmit(0x84, 0xDB, 0xFF, 0xFF, F9_DEFINITION),
              "Create F9 authority key");
        });
  }

  private byte[] defineAndGenerateAuthority() {
    defineAuthority();
    return generateAuthority();
  }

  /** Generates F9 over SCP and returns the 65-octet public point from the 7F49 response. */
  private byte[] generateAuthority() {
    byte[] response =
        withMockedScp(
            () -> {
              assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 generate");
              return collectResponse(
                  transmit(0x84, 0x47, 0x00, KEY_REF_ATTESTATION & 0xFF, F9_GENERATE),
                  "Generate F9");
            });
    assertEquals(0x7F, response[0] & 0xFF);
    assertEquals(0x49, response[1] & 0xFF);
    byte[] point = tlvValue(response, (byte) 0x86);
    assertEquals(65, point.length);
    assertEquals(0x04, point[0]);
    return point;
  }

  private ResponseAPDU prove(byte[] nonce) {
    return transmit(0x84, 0xF9, 0xF9, 0x01, nonce, 256);
  }

  private ResponseAPDU crdF9(byte tag, byte[] value) {
    return transmit(
        0x84,
        0x24,
        ALG_ECC_P256 & 0xFF,
        KEY_REF_ATTESTATION & 0xFF,
        tlv((byte) 0x30, tlv(tag, value)));
  }

  /** Sends {@code 84 24 11 F9 30 82 LL LL 70 82 LL LL <cert>} with command chaining. */
  private ResponseAPDU loadCertificate(byte[] certificate) {
    return transmitChained(
        0x84,
        0x24,
        ALG_ECC_P256 & 0xFF,
        KEY_REF_ATTESTATION & 0xFF,
        tlv((byte) 0x30, tlv((byte) 0x70, certificate)));
  }

  private void loadCertificateOk(final byte[] certificate) {
    ResponseAPDU response =
        withMockedScp(
            () -> {
              assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 certificate load");
              return loadCertificate(certificate);
            });
    assertSw(ISO7816.SW_NO_ERROR, response, "F9 certificate load");
  }

  private void assertLoadRejected(
      TestIssuer issuer, F9Profile profile, int expectedSw, String reason) throws Exception {
    final byte[] certificate = issuer.sign(profile);
    ResponseAPDU response =
        withMockedScp(
            () -> {
              assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before " + reason);
              return loadCertificate(certificate);
            });
    assertSw(expectedSw, response, "F9 certificate with " + reason + " must be rejected");
  }

  private void assertExtensionRejected(
      TestIssuer issuer, byte[] point, String opid, String key, byte[] extension, String reason)
      throws Exception {
    F9Profile profile = issuer.profile(point, opid, DEFAULT_TEMPLATE);
    profile.extensions.put(key, extension);
    assertLoadRejected(issuer, profile, ISO7816.SW_WRONG_DATA, reason);
  }

  private void assertSubjectRejected(TestIssuer issuer, byte[] point, byte[] subject, String reason)
      throws Exception {
    F9Profile profile = issuer.profile(point, opid(), DEFAULT_TEMPLATE);
    profile.subject = subject;
    assertLoadRejected(issuer, profile, ISO7816.SW_WRONG_DATA, reason);
  }

  private void assertF9DefinitionRejected(
      final byte modeContact,
      final byte modeContactless,
      final byte mechanism,
      final byte role,
      final byte attribute,
      final String reason) {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before F9 definition check");
          byte[] request =
              new byte[] {
                0x66,
                0x12,
                (byte) 0x8B,
                0x01,
                (byte) 0xF9,
                (byte) 0x8C,
                0x01,
                modeContact,
                (byte) 0x8D,
                0x01,
                modeContactless,
                (byte) 0x8E,
                0x01,
                mechanism,
                (byte) 0x8F,
                0x01,
                role,
                (byte) 0x90,
                0x01,
                attribute
              };
          assertSw(
              ISO7816.SW_WRONG_DATA,
              transmit(0x84, 0xDB, 0xFF, 0xFF, request),
              "F9 definition must be rejected for " + reason);
        });
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: targets and leaves
  // ---------------------------------------------------------------------------------------------

  private void assertLeafKeyUsage(
      Authority authority,
      TestIssuer issuer,
      byte slot,
      byte algorithm,
      String generateRequest,
      int expectedBit)
      throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm);
    generateKeyOverScp(slot, generateRequest);
    X509Certificate leaf = attest(slot);
    assertValidAttestation(leaf, authority, issuer);
    assertTrue(
        leaf.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()),
        "Leaf KU must be critical");
    boolean[] keyUsage = leaf.getKeyUsage();
    for (int i = 0; i < keyUsage.length; i++) {
      assertEquals(i == expectedBit, keyUsage[i], String.format("slot %02X KU bit %d", slot, i));
    }
  }

  private void assertCanonicalLeaf(
      Authority authority, TestIssuer issuer, byte slot, byte algorithm, String generateRequest)
      throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm);
    generateKeyOverScp(slot, generateRequest);
    X509Certificate leaf = attest(slot);
    assertValidAttestation(leaf, authority, issuer);
    byte[] encoded = leaf.getEncoded();
    assertArrayEquals(
        encoded,
        ASN1Primitive.fromByteArray(encoded).getEncoded(ASN1Encoding.DER),
        String.format("slot %02X leaf must be canonical DER", slot));
    assertTrue(encoded.length <= 0x400, "leaf fits the response buffer");
  }

  private void assertContactlessAttestationBlocked(final byte slot) {
    withContactless(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT over contactless");
          assertSw(
              0x6982,
              transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0)),
              "INS F9 must honor the target contactless access mode");
        });
  }

  private void assertImportedEccTargetIsNotAttestable(byte slot, byte algorithm, int length)
      throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm, ATTR_IMPORTABLE);
    KeyPair target = generateEc(length);
    importKeyElementOverScp(
        algorithm, slot, (byte) 0x86, encodePoint((ECPublicKey) target.getPublic(), length));
    importKeyElementOverScp(
        algorithm,
        slot,
        (byte) 0x87,
        fixed(((java.security.interfaces.ECPrivateKey) target.getPrivate()).getS(), length));
    verifyLocalPin();
    assertSw(
        ISO7816.SW_CONDITIONS_NOT_SATISFIED,
        transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0)),
        String.format("Imported key %02X must not be attestable", slot));
  }

  private X509Certificate attest(byte slot) throws Exception {
    verifyLocalPin();
    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 256));
    return parseCertificate(
        collectResponse(response, "INS F9 should return an attestation certificate"));
  }

  private void verifyLocalPin() {
    assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before attestation PIN authorization");
    assertSw(
        ISO7816.SW_NO_ERROR,
        transmit(0x00, 0x20, 0x00, LOCAL_PIN_REFERENCE & 0xFF, LOCAL_PIN),
        "Verify local PIN before attesting a Table 5 protected key");
  }

  private void createAsymmetricKeyOverScp(byte slot, byte algorithm) {
    createAsymmetricKeyOverScp(slot, algorithm, ATTR_NONE);
  }

  private void createAsymmetricKeyOverScp(byte slot, byte algorithm, byte attribute) {
    byte modeContact;
    byte modeContactless;
    if (slot == SLOT_CARD_AUTHENTICATION) {
      modeContact = ACCESS_MODE_ALWAYS;
      modeContactless = ACCESS_MODE_ALWAYS;
    } else {
      modeContact = slot == SLOT_SIGNATURE ? ACCESS_MODE_PIN_ALWAYS : ACCESS_MODE_PIN;
      modeContactless = (byte) (ACCESS_MODE_VCI | modeContact);
    }
    createAsymmetricKeyOverScp(slot, algorithm, modeContact, modeContactless, attribute);
  }

  private void createAsymmetricKeyOverScp(
      final byte slot,
      final byte algorithm,
      final byte modeContact,
      final byte modeContactless,
      final byte attribute) {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before create-key");
          byte[] request =
              new byte[] {
                0x66,
                0x12,
                (byte) 0x8B,
                0x01,
                slot,
                (byte) 0x8C,
                0x01,
                modeContact,
                (byte) 0x8D,
                0x01,
                modeContactless,
                (byte) 0x8E,
                0x01,
                algorithm,
                (byte) 0x8F,
                0x01,
                operationalRole(slot),
                (byte) 0x90,
                0x01,
                attribute
              };
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmit(0x84, 0xDB, 0xFF, 0xFF, request),
              String.format("Create target key %02X", slot));
        });
    setLocalPinOverScp(LOCAL_PIN);
  }

  private static byte operationalRole(byte slot) {
    if ((slot >= (byte) 0x82 && slot <= (byte) 0x95) || slot == SLOT_KEY_MANAGEMENT) {
      return (byte) 0x02;
    }
    return (byte) 0x04;
  }

  private byte[] generateKeyOverScp(final byte slot, final String generateRequest) {
    return withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before generate-key");
          return collectResponse(
              transmit(0x84, 0x47, 0x00, slot & 0xFF, hex(generateRequest)),
              String.format("Generate target key %02X", slot));
        });
  }

  private void importKeyElementOverScp(
      final byte algorithm, final byte slot, final byte tag, final byte[] value) {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before key element import");
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmitChained(
                  0x84, 0x24, algorithm & 0xFF, slot & 0xFF, tlv((byte) 0x30, tlv(tag, value))),
              "Import key element");
        });
  }

  private void createDataObjectOverScp(final byte id) {
    withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before create-object");
          byte[] objectId = new byte[] {(byte) 0x5F, (byte) 0xC1, id};
          byte[] create =
              tlv(
                  (byte) 0x64,
                  concat(tlv((byte) 0x8B, objectId), hex("8C017F8D017F91019B92021000")));
          assertSw(ISO7816.SW_NO_ERROR, transmit(0x84, 0xDB, 0xFF, 0xFF, create), "Create object");
          assertSw(
              ISO7816.SW_NO_ERROR,
              transmit(
                  0x84,
                  0xDB,
                  0x3F,
                  0xFF,
                  concat(new byte[] {0x5C, 0x03, 0x5F, (byte) 0xC1, id}, hex("530101"))),
              "Populate data object");
        });
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: status and applet state
  // ---------------------------------------------------------------------------------------------

  private byte[] statusResponse() {
    return withMockedScp(
        () -> {
          assertSw(ISO7816.SW_NO_ERROR, selectApplet(), "SELECT before GET STATUS");
          ResponseAPDU response = transmit(0x80, 0xCB, 0xFF, 0xFF, hex("5C032F4753"), 0);
          assertSw(ISO7816.SW_NO_ERROR, response, "GET STATUS");
          byte[] data = response.getData();
          assertEquals(0x53, data[0] & 0xFF);
          return Arrays.copyOfRange(data, contentOffset(data, 0), data.length);
        });
  }

  private byte[] statusValue(byte tag) {
    return tlvValue(statusResponse(), tag);
  }

  private void assertStatusLacks(byte tag) {
    byte[] status = statusResponse();
    int offset = 0;
    while (offset < status.length) {
      assertTrue(status[offset] != tag, String.format("GET STATUS must not carry %02X", tag));
      offset = contentOffset(status, offset) + derLength(status, offset + 1);
    }
  }

  private byte authorityState() {
    return statusValue((byte) 0x89)[0];
  }

  /** Overwrites the persistent authority state inside the installed applet instance. */
  private void setAuthorityState(byte state) throws Exception {
    AutoCloseable context = (AutoCloseable) engine.getClass().getMethod("asCurrent").invoke(engine);
    try {
      Applet applet = unwrapApplet(engine.getApplet(OPENFIPS201_AID));
      Object piv = field(applet, "piv");
      Object attestation = field(piv, "attestation");
      Field stateField = attestation.getClass().getDeclaredField("authorityState");
      stateField.setAccessible(true);
      stateField.setByte(attestation, state);
    } finally {
      context.close();
    }
  }

  private static Object field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static Applet unwrapApplet(Applet appletProxy) throws Exception {
    if (appletProxy.getClass().getName().equals(OpenFIPS201.class.getName())) return appletProxy;
    for (Field proxyField : appletProxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet
            && value.getClass().getName().equals(OpenFIPS201.class.getName())) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: verification
  // ---------------------------------------------------------------------------------------------

  /** PKIX root -> SAM -> F9 -> leaf, plus byte-exact name and key-identifier linkage. */
  private static void assertValidAttestation(
      X509Certificate leaf, Authority authority, TestIssuer issuer) throws Exception {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    CertPath path =
        factory.generateCertPath(Arrays.asList(leaf, authority.certificate, issuer.sam));
    PKIXParameters parameters =
        new PKIXParameters(Collections.singleton(new TrustAnchor(issuer.root, null)));
    parameters.setRevocationEnabled(false);
    parameters.setDate(VALIDATION_DATE);
    CertPathValidator.getInstance("PKIX").validate(path, parameters);

    assertArrayEquals(
        authority.certificate.getSubjectX500Principal().getEncoded(),
        leaf.getIssuerX500Principal().getEncoded(),
        "leaf issuer must equal the F9 subject");
    byte[] aki = leaf.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    assertNotNull(aki);
    assertArrayEquals(
        authority.ski,
        AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(aki).getOctets())
            .getKeyIdentifier(),
        "leaf AKI must equal the F9 SKI");
  }

  private static boolean verifyPop(byte[] signature, byte[] nonce, byte[] point) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKeyFromPoint(point));
    verifier.update("OPF9POP".getBytes(StandardCharsets.US_ASCII));
    verifier.update(nonce);
    verifier.update(point);
    return verifier.verify(signature);
  }

  private static PublicKey publicKeyFromPoint(byte[] point) throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
    ECPoint w =
        new ECPoint(
            new BigInteger(1, Arrays.copyOfRange(point, 1, 33)),
            new BigInteger(1, Arrays.copyOfRange(point, 33, 65)));
    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, spec));
  }

  /** RFC 7093 Section 2 method 1: leftmost 160 bits of SHA-256 over the subjectPublicKey. */
  private static byte[] rfc7093KeyId(byte[] subjectPublicKey) throws Exception {
    return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(subjectPublicKey), 20);
  }

  private static byte[] ski(byte[] point) throws Exception {
    return tlv((byte) 0x04, rfc7093KeyId(point));
  }

  private static X509Certificate parseCertificate(byte[] der) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
  }

  private static java.util.Set<String> allExtensionOids(X509Certificate cert) {
    java.util.Set<String> oids = new java.util.HashSet<String>();
    oids.addAll(cert.getCriticalExtensionOIDs());
    oids.addAll(cert.getNonCriticalExtensionOIDs());
    return oids;
  }

  private static byte[] octets(ASN1Sequence sequence, int index) {
    return ASN1OctetString.getInstance(sequence.getObjectAt(index)).getOctets();
  }

  private static String capPlatformId() throws Exception {
    String capPath = System.getProperty("cap.path");
    Assumptions.assumeTrue(capPath != null, "cap.path identifies the CAP build descriptor");
    Properties properties = new Properties();
    InputStream input = new FileInputStream(capPath + ".properties");
    try {
      properties.load(input);
    } finally {
      input.close();
    }
    String platform = properties.getProperty("platform.id");
    assertNotNull(platform, "CAP descriptor must name platform.id");
    return platform;
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: OPID and names
  // ---------------------------------------------------------------------------------------------

  /**
   * Returns a canonical 17-digit OPID {@code IIII || E || L}: issuer 1234, twelve random digits
   * standing in for the enciphered value, and the Luhn check digit.
   */
  static String opid() {
    StringBuilder digits = new StringBuilder("1234");
    for (int i = 0; i < 12; i++) digits.append((char) ('0' + RANDOM.nextInt(10)));
    return withCheckDigit(digits.toString());
  }

  /** Appends the Luhn mod-10 check digit computed over the printed digits. */
  static String withCheckDigit(String payload) {
    int sum = 0;
    boolean doubled = true;
    for (int i = payload.length() - 1; i >= 0; i--) {
      int digit = payload.charAt(i) - '0';
      if (doubled) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      doubled = !doubled;
    }
    return payload + (char) ('0' + (10 - sum % 10) % 10);
  }

  private static RDN serialNumber(String opid) {
    return new RDN(BCStyle.SERIALNUMBER, new DERPrintableString(opid));
  }

  static byte[] subjectWithOpid(X500Name template, String opid) throws Exception {
    return subject(template, serialNumber(opid));
  }

  private static byte[] subject(X500Name template, RDN... extra) throws Exception {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    for (RDN rdn : template.getRDNs()) builder.addMultiValuedRDN(rdn.getTypesAndValues());
    for (RDN rdn : extra) builder.addMultiValuedRDN(rdn.getTypesAndValues());
    return builder.build().getEncoded(ASN1Encoding.DER);
  }

  private static byte[] extension(ASN1ObjectIdentifier oid, boolean critical, byte[] value)
      throws Exception {
    return tlv(
        (byte) 0x30,
        concat(oid.getEncoded(), critical ? hex("0101FF") : new byte[0], tlv((byte) 0x04, value)));
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers: crypto primitives
  // ---------------------------------------------------------------------------------------------

  private static String repeated(char value, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, value);
    return new String(chars);
  }

  private static byte[] randomBytes(int length) {
    byte[] bytes = new byte[length];
    RANDOM.nextBytes(bytes);
    return bytes;
  }

  private static byte signatureAlgorithm() {
    return isCs7Build() ? ALG_ECC_P384 : ALG_ECC_P256;
  }

  private static String signatureGenerateRequest() {
    return isCs7Build() ? "AC03800114" : "AC03800111";
  }

  private static boolean isCs7Build() {
    return "CS7".equalsIgnoreCase(System.getProperty("vci.suite", "CS2"));
  }

  private static KeyPair generateEc(int coordinateLength) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(
        new ECGenParameterSpec(coordinateLength == 32 ? "secp256r1" : "secp384r1"));
    return generator.generateKeyPair();
  }

  private static byte[] encodePoint(ECPublicKey publicKey, int coordinateLength) {
    ECPoint point = publicKey.getW();
    return concat(
        new byte[] {(byte) 0x04},
        fixed(point.getAffineX(), coordinateLength),
        fixed(point.getAffineY(), coordinateLength));
  }

  private static byte[] fixed(BigInteger integer, int length) {
    byte[] encoded = integer.toByteArray();
    byte[] out = new byte[length];
    int copyLength = Math.min(encoded.length, length);
    System.arraycopy(encoded, encoded.length - copyLength, out, length - copyLength, copyLength);
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // Test issuer: root CA and Issuer SAM stand-in
  // ---------------------------------------------------------------------------------------------

  private static final class Authority {
    final byte[] point;
    final byte[] certificateDer;
    final X509Certificate certificate;
    final byte[] ski;
    final boolean proofVerified;

    Authority(
        byte[] point,
        byte[] certificateDer,
        X509Certificate certificate,
        byte[] ski,
        boolean proofVerified) {
      this.point = point;
      this.certificateDer = certificateDer;
      this.certificate = certificate;
      this.ski = ski;
      this.proofVerified = proofVerified;
    }
  }

  /** Byte-level F9 certificate profile; each field is a complete DER encoding. */
  private static final class F9Profile {
    byte[] version = hex("A003020102");
    byte[] serial;
    byte[] tbsAlgorithm = ECDSA_WITH_SHA256;
    byte[] signatureAlgorithm = ECDSA_WITH_SHA256;
    byte[] issuer;
    byte[] validity;
    byte[] subject;
    byte[] spki;
    byte[] beforeExtensions = new byte[0];
    final Map<String, byte[]> extensions = new LinkedHashMap<String, byte[]>();
    byte[] trailing = new byte[0];
  }

  private static final byte[] ECDSA_WITH_SHA256 = hex("300A06082A8648CE3D040302");
  private static final byte[] P256_SPKI_PREFIX =
      hex("3059301306072A8648CE3D020106082A8648CE3D030107034200");

  /** Root CA and SAM CA (CA:TRUE pathLen 1) that issue F9 certificates in the SAM profile. */
  static final class TestIssuer {
    final KeyPair rootKey;
    final KeyPair samKey;
    final X509Certificate root;
    final X509Certificate sam;
    final byte[] samSki;

    private TestIssuer(
        KeyPair rootKey, KeyPair samKey, X509Certificate root, X509Certificate sam, byte[] samSki) {
      this.rootKey = rootKey;
      this.samKey = samKey;
      this.root = root;
      this.sam = sam;
      this.samSki = samSki;
    }

    static TestIssuer create() throws Exception {
      KeyPair rootKey = generateEc(32);
      KeyPair samKey = generateEc(32);
      X500Name rootName = new X500Name("C=US,O=OpenPhysical Test,CN=Test Root CA");
      X500Name samName = new X500Name("C=US,O=OpenPhysical Test,CN=Test Issuer SAM");
      byte[] rootSki = keyIdOf(rootKey.getPublic());
      byte[] samSki = keyIdOf(samKey.getPublic());

      JcaX509v3CertificateBuilder rootBuilder =
          new JcaX509v3CertificateBuilder(
              rootName,
              BigInteger.ONE,
              Date.from(Instant.parse("2000-01-01T00:00:00Z")),
              Date.from(Instant.parse("2099-12-31T00:00:00Z")),
              rootName,
              rootKey.getPublic());
      rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      rootBuilder.addExtension(
          Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      rootBuilder.addExtension(
          Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(rootSki));
      X509Certificate root = build(rootBuilder, rootKey);

      JcaX509v3CertificateBuilder samBuilder =
          new JcaX509v3CertificateBuilder(
              rootName,
              BigInteger.valueOf(2),
              Date.from(Instant.parse("2001-01-01T00:00:00Z")),
              Date.from(Instant.parse("2098-12-31T00:00:00Z")),
              samName,
              samKey.getPublic());
      samBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
      samBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
      samBuilder.addExtension(
          Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(samSki));
      samBuilder.addExtension(
          Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(rootSki));
      X509Certificate sam = build(samBuilder, rootKey);
      return new TestIssuer(rootKey, samKey, root, sam, samSki);
    }

    /** Returns the default SAM-profile F9 certificate for the point, OPID and template. */
    F9Profile profile(byte[] point, String opid, X500Name template) throws Exception {
      F9Profile profile = new F9Profile();
      byte[] serial = randomBytes(16);
      profile.serial = new ASN1Integer(new BigInteger(1, serial)).getEncoded();
      profile.issuer = sam.getSubjectX500Principal().getEncoded();
      profile.validity =
          new DERSequence(
                  new ASN1Encodable[] {
                    new Time(Date.from(Instant.parse("2020-01-01T00:00:00Z"))),
                    new Time(Date.from(Instant.parse("2060-01-01T00:00:00Z")))
                  })
              .getEncoded(ASN1Encoding.DER);
      profile.subject = subjectWithOpid(template, opid);
      profile.spki = concat(P256_SPKI_PREFIX, point);
      profile.extensions.put(
          "bc", extension(Extension.basicConstraints, true, hex("30060101FF020100")));
      profile.extensions.put("ku", extension(Extension.keyUsage, true, hex("03020204")));
      profile.extensions.put("ski", extension(Extension.subjectKeyIdentifier, false, ski(point)));
      profile.extensions.put(
          "aki", extension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier()));
      profile.extensions.put(
          "issuance",
          extension(
              new ASN1ObjectIdentifier("1.3.6.1.4.1.57923.20.10.10.2"), false, hex("3003020101")));
      return profile;
    }

    byte[] authorityKeyIdentifier() {
      return tlv((byte) 0x30, tlv((byte) 0x80, samSki));
    }

    /** Assembles the TBS certificate, signs it with the SAM key, and returns the certificate. */
    byte[] sign(F9Profile profile) throws Exception {
      List<byte[]> parts = new ArrayList<byte[]>();
      parts.add(profile.version);
      parts.add(profile.serial);
      parts.add(profile.tbsAlgorithm);
      parts.add(profile.issuer);
      parts.add(profile.validity);
      parts.add(profile.subject);
      parts.add(profile.spki);
      parts.add(profile.beforeExtensions);
      if (!profile.extensions.isEmpty()) {
        byte[] all = new byte[0];
        for (byte[] extension : profile.extensions.values()) all = concat(all, extension);
        parts.add(tlv((byte) 0xA3, tlv((byte) 0x30, all)));
      }
      byte[] tbs = tlv((byte) 0x30, concat(parts.toArray(new byte[0][])));
      Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(samKey.getPrivate());
      signer.update(tbs);
      byte[] signature = signer.sign();
      byte[] certificate =
          tlv(
              (byte) 0x30,
              concat(
                  tbs,
                  profile.signatureAlgorithm,
                  tlv((byte) 0x03, concat(new byte[] {0x00}, signature))));
      return concat(certificate, profile.trailing);
    }

    private static byte[] keyIdOf(PublicKey key) throws Exception {
      return rfc7093KeyId(
          SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getBytes());
    }

    private static X509Certificate build(JcaX509v3CertificateBuilder builder, KeyPair signer)
        throws Exception {
      ContentSigner contentSigner =
          new JcaContentSignerBuilder("SHA256withECDSA")
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(signer.getPrivate());
      X509CertificateHolder holder = builder.build(contentSigner);
      return new JcaX509CertificateConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCertificate(holder);
    }
  }
}
