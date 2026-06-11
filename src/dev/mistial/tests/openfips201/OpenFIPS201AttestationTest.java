package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import javacard.framework.APDU;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

@Timeout(value = 35, unit = TimeUnit.SECONDS)
class OpenFIPS201AttestationTest extends OpenFIPS201TestSupport {

  private static final byte ALG_RSA_1024 = (byte) 0x06;
  private static final byte ALG_RSA_2048 = (byte) 0x07;
  private static final byte ALG_AES_128 = (byte) 0x08;
  private static final byte ALG_ECC_P256 = (byte) 0x11;
  private static final byte ALG_ECC_P384 = (byte) 0x14;
  private static final byte SLOT_AUTHENTICATION = (byte) 0x9A;
  private static final byte SLOT_SIGNATURE = (byte) 0x9C;
  private static final byte SLOT_KEY_MANAGEMENT = (byte) 0x9D;
  private static final byte SLOT_RETIRED = (byte) 0x82;
  private static final byte KEY_REF_CARD_MANAGEMENT = (byte) 0x9B;
  private static final byte LOCAL_PIN_REFERENCE = (byte) 0x80;
  private static final byte ACCESS_MODE_PIN = (byte) 0x01;
  private static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F;
  private static final byte ACCESS_MODE_NEVER = (byte) 0x00;
  private static final byte ATTR_IMPORTABLE = (byte) 0x10;
  private static final byte[] LOCAL_PIN = hex("313233343536FFFF");

  @BeforeAll
  static void installProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void attestationCertificateValidatesForVariedIssuerSubject() throws Exception {
    Authority authority =
        Authority.create(new X500Name("OU=Secure Element+CN=Authority One,O=Example,C=US"));

    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    X509Certificate cert = attest(SLOT_AUTHENTICATION);
    assertValidAttestation(cert, authority);
  }

  @Test
  void attestationCertificateValidatesForRsaAndEccTargets() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Root,O=Example,C=US"));
    setAuthorityOverScp(authority);

    assertGeneratedTargetAttests(authority, SLOT_AUTHENTICATION, ALG_ECC_P256, "AC03800111");
    assertGeneratedTargetAttests(authority, SLOT_SIGNATURE, ALG_ECC_P384, "AC03800114");
    assertGeneratedTargetAttests(authority, SLOT_KEY_MANAGEMENT, ALG_RSA_1024, "AC03800106");
    assertGeneratedTargetAttests(authority, SLOT_RETIRED, ALG_RSA_2048, "AC03800107");
  }

  @Test
  void attestationHandlesMaximumIssuerProfileWithRsa2048Target() throws Exception {
    // Exercise the maximum supported issuer subject size together with the largest supported
    // target key (RSA-2048). The resulting certificate must fit in the applet's response buffer
    // size (LENGTH_CERT_BUFFER); DERWriter will fail with SW_FILE_FULL on overflow.
    Authority authority =
        Authority.create(
            new X500Name("CN=" + repeated('C', 50) + ",O=" + repeated('O', 40) + ",C=US"));
    assertTrue(
        authority.subjectDer.length > 0x70 && authority.subjectDer.length <= 0x80,
        "Test subject must sit at the top of the supported issuer subject range, got "
            + authority.subjectDer.length);

    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_KEY_MANAGEMENT, ALG_RSA_2048);
    generateKeyOverScp(SLOT_KEY_MANAGEMENT, "AC03800107");

    X509Certificate cert = attest(SLOT_KEY_MANAGEMENT);
    assertValidAttestation(cert, authority);
  }

  private static String repeated(char value, int count) {
    char[] chars = new char[count];
    java.util.Arrays.fill(chars, value);
    return new String(chars);
  }

  @Test
  void authorityImportRequiresSecureChannelEvenAfterAdminAuthentication() throws Exception {
    // Management-key authentication alone is not sufficient for F9 import because the authority
    // scalar and issuer profile must not cross the wire in plaintext.
    Authority authority = Authority.create(new X500Name("CN=Plaintext Rejection,O=Example"));
    byte[] managementKey = keyMaterialAes128((byte) 0x57);

    provisionManagementKeyAndF9DefinitionOverScp(managementKey);
    authenticateManagementKey(managementKey);

    ResponseAPDU response =
        transmit(
            0x00,
            0x24,
            ALG_ECC_P256 & 0xFF,
            0xF9,
            tlv((byte) 0x30, tlv((byte) 0x86, authority.publicPoint)));
    assertSw(
        0x6982,
        response,
        "F9 authority material must not be accepted outside encrypted and MACed SCP");
  }

  @Test
  void rsaAttestationCertificateContainsGeneratedPublicKey() throws Exception {
    // RSA SPKI is built from JavaCard key APIs that write into caller-provided buffers. Compare
    // against GENERATE's public-key response so the certificate is checked for key fidelity.
    Authority authority = Authority.create(new X500Name("CN=RSA Public Key Match,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_KEY_MANAGEMENT, ALG_RSA_2048);
    byte[] generatedPublicKey = generateKeyOverScp(SLOT_KEY_MANAGEMENT, "AC03800107");

    RSAPublicKey attestedPublicKey = (RSAPublicKey) attest(SLOT_KEY_MANAGEMENT).getPublicKey();
    assertEquals(
        new BigInteger(1, tlvValue(generatedPublicKey, (byte) 0x81)),
        attestedPublicKey.getModulus(),
        "RSA attestation certificate must contain the generated modulus");
    assertEquals(
        new BigInteger(1, tlvValue(generatedPublicKey, (byte) 0x82)),
        attestedPublicKey.getPublicExponent(),
        "RSA attestation certificate must contain the generated public exponent");
  }

  @Test
  void setAuthorityClearsExistingKeyMaterialAndDataObjectContents() throws Exception {
    createDataObjectOverScp((byte) 0x5A);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);

    Authority authority = Authority.create(new X500Name("CN=Provisioning Reset,O=Example"));
    setAuthorityOverScp(authority);

    assertSw(
        0x6A82,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC15A")),
        "Authority commit should clear existing data object contents");
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
  }

  @Test
  void authorityKeyRotationWaitsForBothKeyElementsBeforeCommit() throws Exception {
    Authority original = Authority.create(new X500Name("CN=Original Authority,O=Example"));
    setAuthorityOverScp(original);
    createDataObjectOverScp((byte) 0x5A);

    Authority rotated = Authority.create(new X500Name("CN=Rotated Authority,O=Example"));
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x86, rotated.publicPoint);
    assertSw(
        0x9000,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC15A")),
        "Partial F9 key rotation must not clear existing data");

    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x87, rotated.privateScalar);
    assertSw(
        0x6A82,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC15A")),
        "Complete F9 key rotation should clear existing data");
  }

  @Test
  void authorityClearElementResetsCommittedAuthority() throws Exception {
    // The clear element travels over the wire as tag E0 inside the key-update SEQUENCE. This is
    // the provisioning command used before replacing an existing F9 authority.
    Authority authority = Authority.create(new X500Name("CN=Clear Element,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0xE0, new byte[0]);

    ResponseAPDU response =
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0));
    assertSw(0x6985, response, "Cleared authority must no longer attest");
  }

  @Test
  void authorityMetadataReimportCommitsAndClearsExistingObjects() throws Exception {
    Authority original = Authority.create(new X500Name("CN=Original Metadata,O=Example"));
    setAuthorityOverScp(original);
    createDataObjectOverScp((byte) 0x5A);

    Authority updated = Authority.create(new X500Name("CN=Updated Metadata,O=Example"));
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x92, updated.subjectDer);

    assertSw(
        0x6A82,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC15A")),
        "F9 metadata re-import should recommit the authority and clear existing data");
  }

  @Test
  void importedTargetKeysAreNotAttestableForAllSupportedAlgorithms() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Import Rejection,O=Example"));
    setAuthorityOverScp(authority);

    assertImportedEccTargetIsNotAttestable(SLOT_AUTHENTICATION, ALG_ECC_P256, 32);
    assertImportedEccTargetIsNotAttestable(SLOT_SIGNATURE, ALG_ECC_P384, 48);
    assertImportedRsaTargetIsNotAttestable(SLOT_KEY_MANAGEMENT, ALG_RSA_1024, 128);
    assertImportedRsaTargetIsNotAttestable(SLOT_RETIRED, ALG_RSA_2048, 256);
  }

  @Test
  void authorityCommitRejectsMismatchedKeyPairWithoutPurge() throws Exception {
    createDataObjectOverScp((byte) 0x5A);

    Authority mismatched = Authority.create(new X500Name("CN=Bad Authority,O=Example"));
    KeyPair other = generateEcP256();
    byte[] badPrivate = fixed(((ECPrivateKey) other.getPrivate()).getS(), 32);

    ResponseAPDU failed =
        setAuthorityOverScpAndReturn(
            mismatched.publicPoint, badPrivate, mismatched.subjectDer, mismatched.validityDer);
    assertSw(0x6A80, failed, "Mismatched authority key pair must be rejected");

    assertSw(
        0x9000,
        transmit(0x00, 0xCB, 0x3F, 0xFF, hex("5C035FC15A")),
        "Rejected authority commit must preserve existing data objects");
  }

  @Test
  void authorityImportRejectsTruncatedSubjectLongFormLength() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Truncated DER,O=Example"));

    ResponseAPDU badSubject =
        stageAuthorityAndImportElement(authority, (byte) 0x92, hex("3081"), false);
    assertSw(0x6A80, badSubject, "Truncated long-form subject length must be rejected");
  }

  @Test
  void authorityImportRejectsTruncatedValidityLongFormLength() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Truncated DER,O=Example"));

    ResponseAPDU badValidity =
        stageAuthorityAndImportElement(authority, (byte) 0x93, hex("308200"), true);
    assertSw(0x6A80, badValidity, "Truncated long-form validity length must be rejected");
  }

  @Test
  void attestBeforeAuthorityProvisionedFails() throws Exception {
    assertSw(0x9000, selectApplet(), "SELECT before attestation attempt");
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    ResponseAPDU response =
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0));
    assertSw(0x6985, response, "Attestation before authority is provisioned must return 6985");
  }

  @Test
  void attestNonExistentSlotFails() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Attestation CA,O=Example"));
    setAuthorityOverScp(authority);

    ResponseAPDU response =
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0));
    assertSw(0x6A88, response, "Attestation of non-existent slot key must return 6A88");
  }

  @Test
  void attestationRequiresTargetSlotPinWhenTargetAclRequiresPin() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=ACL Required,O=Example"));
    setAuthorityOverScp(authority);
    setLocalPinOverScp(LOCAL_PIN);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256, ACCESS_MODE_PIN, ACCESS_MODE_PIN);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    ResponseAPDU blocked =
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0));
    assertSw(0x6982, blocked, "INS F9 must honor the target key access mode");

    assertSw(
        0x9000,
        transmit(0x00, 0x20, 0x00, LOCAL_PIN_REFERENCE & 0xFF, LOCAL_PIN),
        "Verify local PIN");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority);
  }

  @Test
  void attestationHonorsTargetContactlessAccessMode() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Contactless ACL,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(
        SLOT_AUTHENTICATION, ALG_ECC_P256, ACCESS_MODE_ALWAYS, ACCESS_MODE_NEVER);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    try (MockedStatic<APDU> mockedApdu = Mockito.mockStatic(APDU.class)) {
      mockedApdu
          .when(APDU::getProtocol)
          .thenReturn((byte) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1));
      assertSw(
          0x9000, selectApplet(), "SELECT over contactless should succeed before target ACL check");
      ResponseAPDU blocked =
          transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0));
      assertSw(0x6982, blocked, "INS F9 must honor the target contactless access mode");
    }
  }

  @Test
  void attestRejectsUnattestableSlots() throws Exception {
    assertSw(0x9000, selectApplet(), "SELECT before slot validation checks");

    // The attestation authority itself and the management key are never attestable. The slot
    // check fires before any authority or key lookup, so no provisioning is required here.
    assertSw(
        0x6A86,
        transmit(new CommandAPDU(0x00, 0xF9, 0xF9, 0x00, 0)),
        "INS F9 must reject the attestation authority slot");
    assertSw(
        0x6A86,
        transmit(new CommandAPDU(0x00, 0xF9, KEY_REF_CARD_MANAGEMENT & 0xFF, 0x00, 0)),
        "INS F9 must reject the management key slot");
  }

  @Test
  void attestEnforcesRetiredSlotRangeBoundaries() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Slot Range,O=Example"));
    setAuthorityOverScp(authority);

    assertSw(
        0x6A86,
        transmit(new CommandAPDU(0x00, 0xF9, 0x81, 0x00, 0)),
        "Slot 81 sits below the retired-slot range");
    assertSw(
        0x6A86,
        transmit(new CommandAPDU(0x00, 0xF9, 0x96, 0x00, 0)),
        "Slot 96 sits above the retired-slot range");

    createAsymmetricKeyOverScp((byte) 0x95, ALG_ECC_P256);
    generateKeyOverScp((byte) 0x95, "AC03800111");
    assertValidAttestation(attest((byte) 0x95), authority);
  }

  @Test
  void generateAsymmetricKeypairRejectsAttestationAuthorityReference() {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before F9 generate attempt");
            createF9AuthorityKeyDefinition();
            // The issuer certificate is bound to the imported F9 key; generating a replacement
            // on-card would silently break that correspondence.
            assertSw(
                0x6A86,
                transmit(0x84, 0x47, 0x00, 0xF9, hex("AC03800111")),
                "F9 must never be generated on-card");
          }
        });
  }

  @Test
  void generatedKeyLosesAttestabilityAfterKeyImport() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Origin Flip,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority);

    // Importing key material over a generated key changes its origin; the applet can no longer
    // attest that the slot's key was generated on-card.
    KeyPair replacement = generateEcP256();
    importKeyElementOverScp(
        ALG_ECC_P256,
        SLOT_AUTHENTICATION,
        (byte) 0x86,
        encodePoint((ECPublicKey) replacement.getPublic(), 32));
    importKeyElementOverScp(
        ALG_ECC_P256,
        SLOT_AUTHENTICATION,
        (byte) 0x87,
        fixed(((ECPrivateKey) replacement.getPrivate()).getS(), 32));

    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "A generated key overwritten by import must not be attestable");
  }

  @Test
  void authorityRecommitInvalidatesPreviouslyGeneratedTargets() throws Exception {
    Authority original = Authority.create(new X500Name("CN=First Authority,O=Example"));
    setAuthorityOverScp(original);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), original);

    // Committing a replacement authority is a trust-root change: it wipes non-F9 key material,
    // so targets generated under the previous authority must be regenerated before they attest.
    Authority replacement = Authority.create(new X500Name("CN=Second Authority,O=Example"));
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0xE0, new byte[0]);
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x86, replacement.publicPoint);
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x87, replacement.privateScalar);
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x92, replacement.subjectDer);
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x93, replacement.validityDer);

    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "Targets generated under the previous authority must not attest after a recommit");

    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), replacement);
  }

  @Test
  void attestFailsDuringPartialAuthorityRotation() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Rotation Window,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority);

    // Staging one half of a replacement keypair deactivates the authority. No certificate may be
    // issued while the committed key and the staged key could disagree.
    Authority replacement = Authority.create(new X500Name("CN=Half Staged,O=Example"));
    importKeyElementOverScp(ALG_ECC_P256, (byte) 0xF9, (byte) 0x86, replacement.publicPoint);

    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "No attestation may be issued while an authority rotation is half staged");
  }

  @Test
  void createdButNotGeneratedKeyIsNotAttestable() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=No Material,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);

    assertSw(
        0x6985,
        transmit(new CommandAPDU(0x00, 0xF9, SLOT_AUTHENTICATION & 0xFF, 0x00, 0)),
        "A key definition without generated material must not be attestable");
  }

  @Test
  void authorityImportRejectsOversizeSubject() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Oversize Subject,O=Example"));
    assertSw(
        0x6A84,
        stageAuthorityAndImportElement(authority, (byte) 0x92, new byte[0x81], false),
        "Issuer subjects above 0x80 bytes must be rejected");
  }

  @Test
  void authorityImportRejectsOversizeValidity() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Oversize Validity,O=Example"));
    assertSw(
        0x6A84,
        stageAuthorityAndImportElement(authority, (byte) 0x93, new byte[0x41], true),
        "Validity above 0x40 bytes must be rejected");
  }

  @Test
  void authorityImportRejectsSingleTimeValidity() throws Exception {
    // A single UTCTime: structurally valid DER, but Validity requires exactly two Time values.
    Authority authority = Authority.create(new X500Name("CN=Validity Shape,O=Example"));
    byte[] singleTime = tlv((byte) 0x30, tlv((byte) 0x17, hex("3236303130313030303030305A")));
    assertSw(
        0x6A80,
        stageAuthorityAndImportElement(authority, (byte) 0x93, singleTime, true),
        "Validity must contain exactly two Time values");
  }

  @Test
  void authorityImportRejectsNonTimeValidityMembers() throws Exception {
    // Two INTEGERs: correct cardinality, wrong member tags.
    Authority authority = Authority.create(new X500Name("CN=Validity Members,O=Example"));
    byte[] integers =
        tlv(
            (byte) 0x30,
            concat(tlv((byte) 0x02, new byte[] {0x01}), tlv((byte) 0x02, new byte[] {0x01})));
    assertSw(
        0x6A80,
        stageAuthorityAndImportElement(authority, (byte) 0x93, integers, true),
        "Validity entries must be UTCTime or GeneralizedTime");
  }

  @Test
  void authorityImportRejectsUnknownProfileElementTag() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Unknown Element,O=Example"));
    assertSw(
        0x6A80,
        stageAuthorityAndImportElement(authority, (byte) 0x94, new byte[] {0x00}, true),
        "Unknown F9 element tags must be rejected");
  }

  @Test
  void f9KeyDefinitionShapeIsEnforced() {
    assertF9DefinitionRejected(
        ACCESS_MODE_ALWAYS,
        ACCESS_MODE_NEVER,
        ALG_ECC_P256,
        (byte) 0x04,
        ATTR_IMPORTABLE,
        "contact access mode must be NEVER");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER,
        ACCESS_MODE_ALWAYS,
        ALG_ECC_P256,
        (byte) 0x04,
        ATTR_IMPORTABLE,
        "contactless access mode must be NEVER");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER,
        ACCESS_MODE_NEVER,
        ALG_ECC_P384,
        (byte) 0x04,
        ATTR_IMPORTABLE,
        "mechanism must be ECC P-256");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER,
        ACCESS_MODE_NEVER,
        ALG_ECC_P256,
        (byte) 0x01,
        ATTR_IMPORTABLE,
        "role must be SIGN");
    assertF9DefinitionRejected(
        ACCESS_MODE_NEVER,
        ACCESS_MODE_NEVER,
        ALG_ECC_P256,
        (byte) 0x04,
        (byte) 0x04,
        "attribute must be IMPORTABLE");
  }

  @Test
  void multipleAttestationsInOneSessionShareTheResponseBuffer() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Session Reuse,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");
    createAsymmetricKeyOverScp(SLOT_SIGNATURE, ALG_ECC_P384);
    generateKeyOverScp(SLOT_SIGNATURE, "AC03800114");

    // The response buffer is allocated on the first attestation and shared by every subsequent
    // one; alternating targets exercises reuse across keys and repeated certificate builds.
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority);
    assertValidAttestation(attest(SLOT_SIGNATURE), authority);
    assertValidAttestation(attest(SLOT_AUTHENTICATION), authority);
    assertValidAttestation(attest(SLOT_SIGNATURE), authority);
  }

  @Test
  void attestationCertificateMatchesDocumentedProfile() throws Exception {
    Authority authority = Authority.create(new X500Name("CN=Profile Contract,O=Example"));
    setAuthorityOverScp(authority);
    createAsymmetricKeyOverScp(SLOT_AUTHENTICATION, ALG_ECC_P256);
    generateKeyOverScp(SLOT_AUTHENTICATION, "AC03800111");

    X509Certificate cert = attest(SLOT_AUTHENTICATION);

    assertEquals(
        authority.issuerCertificate.getNotBefore(),
        cert.getNotBefore(),
        "notBefore must be copied from the committed validity profile");
    assertEquals(
        authority.issuerCertificate.getNotAfter(),
        cert.getNotAfter(),
        "notAfter must be copied from the committed validity profile");
    assertEquals(
        new javax.security.auth.x500.X500Principal("CN=PIV Attestation 9A"),
        cert.getSubjectX500Principal(),
        "Subject must name the attested slot");
    assertEquals(-1, cert.getBasicConstraints(), "BasicConstraints must assert CA=false");
    boolean[] keyUsage = cert.getKeyUsage();
    assertTrue(keyUsage != null && keyUsage[0], "KeyUsage must assert digitalSignature");
    for (int i = 1; i < keyUsage.length; i++) {
      assertTrue(!keyUsage[i], "KeyUsage must assert only digitalSignature");
    }
    assertEquals(1, cert.getSerialNumber().signum(), "Serial must be positive");
    assertTrue(cert.getSerialNumber().bitLength() <= 127, "Serial must fit 16 octets");
  }

  private void assertF9DefinitionRejected(
      final byte modeContact,
      final byte modeContactless,
      final byte mechanism,
      final byte role,
      final byte attribute,
      final String reason) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before F9 definition check");
            byte[] request =
                new byte[] {
                  (byte) 0x66,
                  (byte) 0x12,
                  (byte) 0x8B,
                  (byte) 0x01,
                  (byte) 0xF9,
                  (byte) 0x8C,
                  (byte) 0x01,
                  modeContact,
                  (byte) 0x8D,
                  (byte) 0x01,
                  modeContactless,
                  (byte) 0x8E,
                  (byte) 0x01,
                  mechanism,
                  (byte) 0x8F,
                  (byte) 0x01,
                  role,
                  (byte) 0x90,
                  (byte) 0x01,
                  attribute
                };
            assertSw(
                0x6A80,
                transmit(0x84, 0xDB, 0x3F, 0x00, request),
                "F9 definition must be rejected when the " + reason);
          }
        });
  }

  private void assertGeneratedTargetAttests(
      Authority authority, byte slot, byte algorithm, String generateRequest) throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm);
    generateKeyOverScp(slot, generateRequest);
    X509Certificate cert = attest(slot);
    if (algorithm == ALG_RSA_1024) {
      assertSignedAttestation(cert, authority);
    } else {
      assertValidAttestation(cert, authority);
    }
  }

  private void assertImportedEccTargetIsNotAttestable(
      byte slot, byte algorithm, int coordinateLength) throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm);

    KeyPair target = generateEc(coordinateLength);
    byte[] publicPoint = encodePoint((ECPublicKey) target.getPublic(), coordinateLength);
    byte[] privateScalar = fixed(((ECPrivateKey) target.getPrivate()).getS(), coordinateLength);
    importKeyElementOverScp(algorithm, slot, (byte) 0x86, publicPoint);
    importKeyElementOverScp(algorithm, slot, (byte) 0x87, privateScalar);

    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0));
    assertSw(0x6985, response, "Imported ECC target keys must not be attestable");
  }

  private void assertImportedRsaTargetIsNotAttestable(byte slot, byte algorithm, int modulusLength)
      throws Exception {
    createAsymmetricKeyOverScp(slot, algorithm);

    KeyPair target = generateRsa(modulusLength * 8);
    RSAPublicKey publicKey = (RSAPublicKey) target.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) target.getPrivate();
    importKeyElementOverScp(
        algorithm, slot, (byte) 0x81, fixed(publicKey.getModulus(), modulusLength));
    importKeyElementOverScp(algorithm, slot, (byte) 0x82, fixed(publicKey.getPublicExponent(), 3));
    importKeyElementOverScp(
        algorithm, slot, (byte) 0x83, fixed(privateKey.getPrivateExponent(), modulusLength));

    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0));
    assertSw(0x6985, response, "Imported RSA target keys must not be attestable");
  }

  private X509Certificate attest(byte slot) throws Exception {
    ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xF9, slot & 0xFF, 0x00, 0));
    byte[] certificate =
        collectResponse(response, "INS F9 should return an attestation certificate");
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate));
  }

  private byte[] collectResponse(ResponseAPDU response, String context) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ResponseAPDU current = response;
    while ((current.getSW() & 0xFF00) == 0x6100) {
      out.write(current.getData(), 0, current.getData().length);
      int le = current.getSW2() == 0 ? 256 : current.getSW2();
      current = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le));
    }
    assertSw(0x9000, current, context);
    out.write(current.getData(), 0, current.getData().length);
    return out.toByteArray();
  }

  private static void assertValidAttestation(X509Certificate cert, Authority authority)
      throws Exception {
    assertSignedAttestation(cert, authority);

    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    CertPath path = factory.generateCertPath(Collections.singletonList(cert));
    PKIXParameters parameters =
        new PKIXParameters(
            Collections.singleton(new TrustAnchor(authority.issuerCertificate, null)));
    parameters.setRevocationEnabled(false);
    CertPathValidator.getInstance("PKIX").validate(path, parameters);
  }

  private static void assertSignedAttestation(X509Certificate cert, Authority authority)
      throws Exception {
    cert.verify(authority.issuerCertificate.getPublicKey());
    assertEquals(
        authority.issuerCertificate.getSubjectX500Principal(),
        cert.getIssuerX500Principal(),
        "Generated certificate issuer must equal configured authority subject");
  }

  private void setAuthorityOverScp(Authority authority) {
    assertSw(
        0x9000,
        setAuthorityOverScpAndReturn(
            authority.publicPoint,
            authority.privateScalar,
            authority.subjectDer,
            authority.validityDer),
        "Set attestation authority should succeed");
  }

  private ResponseAPDU setAuthorityOverScpAndReturn(
      byte[] publicPoint, byte[] privateScalar, byte[] subjectDer, byte[] validityDer) {
    final ResponseAPDU[] response = new ResponseAPDU[1];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before authority commit");
            createF9AuthorityKeyDefinition();
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x86, publicPoint))),
                "Stage F9 public key");
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x87, privateScalar))),
                "Stage F9 private key");
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x92, subjectDer))),
                "Stage F9 issuer subject");
            response[0] =
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x93, validityDer)));
          }
        });
    return response[0];
  }

  private ResponseAPDU stageAuthorityAndImportElement(
      final Authority authority, final byte tag, final byte[] value, final boolean includeSubject) {
    final ResponseAPDU[] response = new ResponseAPDU[1];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before malformed authority import");
            createF9AuthorityKeyDefinition();
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x86, authority.publicPoint))),
                "Stage F9 public key");
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_ECC_P256 & 0xFF,
                    0xF9,
                    tlv((byte) 0x30, tlv((byte) 0x87, authority.privateScalar))),
                "Stage F9 private key");
            if (includeSubject) {
              assertSw(
                  0x9000,
                  transmit(
                      0x84,
                      0x24,
                      ALG_ECC_P256 & 0xFF,
                      0xF9,
                      tlv((byte) 0x30, tlv((byte) 0x92, authority.subjectDer))),
                  "Stage F9 issuer subject");
            }
            response[0] =
                transmit(0x84, 0x24, ALG_ECC_P256 & 0xFF, 0xF9, tlv((byte) 0x30, tlv(tag, value)));
          }
        });
    return response[0];
  }

  private void createF9AuthorityKeyDefinition() {
    byte[] request =
        new byte[] {
          (byte) 0x66,
          (byte) 0x12,
          (byte) 0x8B,
          (byte) 0x01,
          (byte) 0xF9,
          (byte) 0x8C,
          (byte) 0x01,
          (byte) 0x00,
          (byte) 0x8D,
          (byte) 0x01,
          (byte) 0x00,
          (byte) 0x8E,
          (byte) 0x01,
          ALG_ECC_P256,
          (byte) 0x8F,
          (byte) 0x01,
          (byte) 0x04,
          (byte) 0x90,
          (byte) 0x01,
          (byte) 0x10
        };
    assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, request), "Create F9 authority key");
  }

  private void createAsymmetricKeyOverScp(final byte slot, final byte algorithm) {
    createAsymmetricKeyOverScp(slot, algorithm, ACCESS_MODE_ALWAYS, ACCESS_MODE_NEVER);
  }

  private void createAsymmetricKeyOverScp(
      final byte slot, final byte algorithm, final byte modeContact, final byte modeContactless) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before create-key");
            byte[] request =
                new byte[] {
                  (byte) 0x66,
                  (byte) 0x12,
                  (byte) 0x8B,
                  (byte) 0x01,
                  slot,
                  (byte) 0x8C,
                  (byte) 0x01,
                  modeContact,
                  (byte) 0x8D,
                  (byte) 0x01,
                  modeContactless,
                  (byte) 0x8E,
                  (byte) 0x01,
                  algorithm,
                  (byte) 0x8F,
                  (byte) 0x01,
                  (byte) 0x04,
                  (byte) 0x90,
                  (byte) 0x01,
                  ATTR_IMPORTABLE
                };
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0x00, request),
                "Create target key should succeed");
          }
        });
  }

  private byte[] generateKeyOverScp(final byte slot, final String generateRequest) {
    final byte[][] result = new byte[0x01][];
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before generate-key");
            result[0] =
                collectResponse(
                    transmit(0x84, 0x47, 0x00, slot & 0xFF, hex(generateRequest)),
                    "Generate target key " + String.format("0x%02X", slot));
          }
        });
    return result[0];
  }

  /**
   * Attestation manages its own PIN and 9B/F9 authority, so the standard test card is not applied.
   */
  @Override
  protected boolean provisionsStandardCard() {
    return false;
  }

  private void createDataObjectOverScp(final byte id) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before create-object");
            byte[] objectId = new byte[] {(byte) 0x5F, (byte) 0xC1, id};
            byte[] create =
                tlv(
                    (byte) 0x64,
                    concat(
                        tlv((byte) 0x8B, objectId),
                        new byte[] {
                          (byte) 0x8C, (byte) 0x01, (byte) 0x7F,
                          (byte) 0x8D, (byte) 0x01, (byte) 0x7F,
                          (byte) 0x91, (byte) 0x01, (byte) 0x9B
                        }));
            assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, create), "Create data object");
            assertSw(
                0x9000,
                transmit(0x84, 0xDB, 0x3F, 0xFF, concat(normalTagList(id), hex("530101"))),
                "Populate data object");
          }
        });
  }

  private void importKeyElementOverScp(
      final byte algorithm, final byte slot, final byte tag, final byte[] value) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before key element import");
            transmitKeyElementImport(algorithm, slot, tlv((byte) 0x30, tlv(tag, value)));
          }
        });
  }

  private void transmitKeyElementImport(byte algorithm, byte slot, byte[] payload) {
    final int chunkLength = 0x80;
    int offset = 0;
    while (offset < payload.length) {
      int length = Math.min(chunkLength, payload.length - offset);
      byte[] chunk = new byte[length];
      System.arraycopy(payload, offset, chunk, 0, length);
      offset += length;

      int cla = offset < payload.length ? 0x94 : 0x84;
      assertSw(
          0x9000,
          transmit(cla, 0x24, algorithm & 0xFF, slot & 0xFF, chunk),
          "Import key element should succeed");
    }
  }

  private void provisionManagementKeyAndF9DefinitionOverScp(final byte[] managementKey) {
    withMockedScp(
        new Runnable() {
          @Override
          public void run() {
            assertSw(0x9000, selectApplet(), "SELECT before SCP provisioning flow");
            // Bind F9 to the default 9B admin key; plaintext 9B authentication must still not
            // authorize F9 material import.
            byte[] createManagementKey =
                new byte[] {
                  (byte) 0x66,
                  (byte) 0x12,
                  (byte) 0x8B,
                  (byte) 0x01,
                  KEY_REF_CARD_MANAGEMENT,
                  (byte) 0x8C,
                  (byte) 0x01,
                  (byte) 0x7F,
                  (byte) 0x8D,
                  (byte) 0x01,
                  (byte) 0x00,
                  (byte) 0x8E,
                  (byte) 0x01,
                  ALG_AES_128,
                  (byte) 0x8F,
                  (byte) 0x01,
                  (byte) 0x01,
                  (byte) 0x90,
                  (byte) 0x01,
                  (byte) 0x11
                };
            assertSw(0x9000, transmit(0x84, 0xDB, 0x3F, 0x00, createManagementKey), "Create 9B");
            assertSw(
                0x9000,
                transmit(
                    0x84,
                    0x24,
                    ALG_AES_128 & 0xFF,
                    KEY_REF_CARD_MANAGEMENT & 0xFF,
                    keyUpdateData(managementKey)),
                "Import 9B");
            createF9AuthorityKeyDefinition();
          }
        });
  }

  private void authenticateManagementKey(byte[] managementKey) {
    assertSw(0x9000, selectApplet(), "SELECT before plaintext management-key authentication");
    ResponseAPDU challengeResponse =
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, hex("7C028100"));
    assertSw(0x9000, challengeResponse, "Management key challenge request");

    byte[] challenge = extractChallenge(challengeResponse.getData());
    byte[] encryptedChallenge = encryptAes128(managementKey, challenge);
    byte[] authResponse =
        concat(
            new byte[] {
              (byte) 0x7C,
              (byte) (encryptedChallenge.length + 2),
              (byte) 0x82,
              (byte) encryptedChallenge.length
            },
            encryptedChallenge);
    assertSw(
        0x9000,
        transmit(0x00, 0x87, ALG_AES_128 & 0xFF, KEY_REF_CARD_MANAGEMENT & 0xFF, authResponse),
        "Plaintext management-key authentication");
  }

  private static byte[] normalTagList(byte id) {
    return new byte[] {(byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, id};
  }

  private static byte[] extractChallenge(byte[] responseData) {
    assertEquals(0x14, responseData.length, "Unexpected AES challenge response length");
    assertEquals(
        (byte) 0x7C, responseData[0], "Challenge must use dynamic authentication template");
    assertEquals((byte) 0x81, responseData[2], "Challenge response must use tag 81");
    assertEquals((byte) 0x10, responseData[3], "AES challenge must be 16 bytes");
    byte[] challenge = new byte[0x10];
    System.arraycopy(responseData, 4, challenge, 0, challenge.length);
    return challenge;
  }

  private static byte[] encryptAes128(byte[] key, byte[] challenge) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
      return cipher.doFinal(challenge);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to encrypt management-key challenge", e);
    }
  }

  private static KeyPair generateEcP256() throws Exception {
    return generateEc(32);
  }

  private static KeyPair generateEc(int coordinateLength) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(
        new ECGenParameterSpec(coordinateLength == 32 ? "secp256r1" : "secp384r1"));
    return generator.generateKeyPair();
  }

  private static KeyPair generateRsa(int keyLength) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keyLength);
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

  private static final class Authority {
    final byte[] publicPoint;
    final byte[] privateScalar;
    final byte[] subjectDer;
    final byte[] validityDer;
    final X509Certificate issuerCertificate;

    private Authority(
        byte[] publicPoint,
        byte[] privateScalar,
        byte[] subjectDer,
        byte[] validityDer,
        X509Certificate issuerCertificate) {
      this.publicPoint = publicPoint;
      this.privateScalar = privateScalar;
      this.subjectDer = subjectDer;
      this.validityDer = validityDer;
      this.issuerCertificate = issuerCertificate;
    }

    static Authority create(X500Name subject) throws Exception {
      KeyPair keyPair = generateEcP256();
      Date notBefore = new Date(946684800000L);
      Date notAfter = new Date(4102444800000L);

      ASN1EncodableVector validity = new ASN1EncodableVector();
      validity.add(new Time(notBefore));
      validity.add(new Time(notAfter));
      byte[] validityDer = new DERSequence(validity).getEncoded();

      ContentSigner signer =
          new JcaContentSignerBuilder("SHA256withECDSA")
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(keyPair.getPrivate());
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      builder.addExtension(
          Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      X509CertificateHolder holder = builder.build(signer);
      X509Certificate certificate =
          new JcaX509CertificateConverter()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .getCertificate(holder);

      return new Authority(
          encodePoint((ECPublicKey) keyPair.getPublic(), 32),
          fixed(((ECPrivateKey) keyPair.getPrivate()).getS(), 32),
          subject.getEncoded(),
          validityDer,
          certificate);
    }
  }
}
