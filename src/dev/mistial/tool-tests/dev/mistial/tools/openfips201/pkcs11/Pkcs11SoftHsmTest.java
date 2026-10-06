/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.CertifiedSigningKey;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** PKCS#11 token initialization, sessions and root key management against SoftHSM2. */
@Tag("softhsm")
class Pkcs11SoftHsmTest {
  private static final byte[] SO_PIN = "so-pin-0123456789".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] USER_PIN = "user-pin-98765".getBytes(StandardCharsets.US_ASCII);

  @TempDir Path temp;

  private String label;
  private Pkcs11Config config;

  @BeforeEach
  void initializeToken() throws Exception {
    SoftHsmFixture.requireSoftHsm();
    label = SoftHsmFixture.uniqueLabel("t-");
    config = SoftHsmFixture.config(label);
    Pkcs11AdminService.initializeToken(config, SO_PIN.clone(), USER_PIN.clone());
    config.pinFile = pinFile("user.pin", USER_PIN).toString();
  }

  @Test
  void initializedTokenIsFoundOnceAndCannotBeInitializedAgain() {
    CryptokiLibrary library = Pkcs11Token.load(config);
    NativeLong slot = Pkcs11Token.findInitializedTokenSlot(library, label);
    assertNotNull(slot);
    assertTrue(
        (Pkcs11Token.tokenFlags(library, slot) & Pkcs11Constants.CKF_USER_PIN_INITIALIZED) != 0);
    assertTrue(Pkcs11AdminService.tokenExists(config));
    assertTrue(Pkcs11AdminService.userPinInitialized(config));

    assertThrows(
        IllegalStateException.class,
        () -> Pkcs11AdminService.initializeToken(config, SO_PIN.clone(), USER_PIN.clone()));
    assertNotNull(Pkcs11Token.findInitializedTokenSlot(library, label));
  }

  @Test
  void initializationRefusesEqualSoAndUserPins() throws Exception {
    Pkcs11Config other = SoftHsmFixture.config(SoftHsmFixture.uniqueLabel("t-"));
    assertThrows(
        IllegalArgumentException.class,
        () -> Pkcs11AdminService.initializeToken(other, USER_PIN.clone(), USER_PIN.clone()));
    assertFalse(Pkcs11AdminService.tokenExists(other));
  }

  @Test
  void wrongPinDoesNotLeakTheSession() throws Exception {
    CryptokiLibrary library = Pkcs11Token.load(config);
    SessionRecorder recorder = new SessionRecorder(library);
    Pkcs11Config wrong = config.copy();
    wrong.pinFile =
        pinFile("wrong.pin", "not-the-pin".getBytes(StandardCharsets.US_ASCII)).toString();

    Pkcs11Exception failure =
        assertThrows(Pkcs11Exception.class, () -> Pkcs11Token.open(recorder.library(), wrong));

    assertTrue(failure.getMessage().contains("C_Login"), failure.getMessage());
    assertEquals(1, recorder.opened.size());
    assertEquals(
        Pkcs11Constants.CKR_SESSION_HANDLE_INVALID, sessionInfo(library, recorder.opened.get(0)));
    assertEquals(
        Pkcs11Constants.CKR_OK,
        library.C_CloseAllSessions(Pkcs11Token.findInitializedTokenSlot(library, label))
            .longValue());
  }

  @Test
  void missingPinSourceDoesNotLeakTheSession() {
    CryptokiLibrary library = Pkcs11Token.load(config);
    SessionRecorder recorder = new SessionRecorder(library);
    Pkcs11Config missing = config.copy();
    missing.pinFile = null;
    missing.pinEnv = "OPENFIPS201_TEST_PIN_THAT_IS_NEVER_SET";

    assertThrows(
        IllegalArgumentException.class, () -> Pkcs11Token.open(recorder.library(), missing));

    assertEquals(1, recorder.opened.size());
    assertEquals(
        Pkcs11Constants.CKR_SESSION_HANDLE_INVALID, sessionInfo(library, recorder.opened.get(0)));
  }

  @Test
  void oneSessionServesSigningAndCmacWithOneLogin() throws Exception {
    CryptokiLibrary library = Pkcs11Token.load(config);
    SessionRecorder recorder = new SessionRecorder(library);
    Pkcs11AdminService admin = new Pkcs11AdminService();
    NativeLong handle;
    try (Pkcs11Session session = Pkcs11Session.open(recorder.library(), config)) {
      admin.ensureRootSigner(session, "root", "CN=Session Root", 30);
      admin.ensureAes256Key(session, "master");
      Pkcs11Config rootKey = config.copy();
      rootKey.keyAlias = "root";
      CertifiedSigningKey signer = CertifiedSigningKey.of(session.signingKey(rootKey));
      byte[] message = "message".getBytes(StandardCharsets.US_ASCII);
      Signature verifier = Signature.getInstance("SHA256withECDSA");
      verifier.initVerify(signer.publicKey());
      verifier.update(message);
      assertTrue(verifier.verify(signer.sign("SHA256withECDSA", message)));

      Pkcs11Config master = config.copy();
      master.keyAlias = "master";
      Pkcs11AesCmacService cmac = new Pkcs11AesCmacService(session);
      byte[] first = cmac.sign(master, new byte[16]);
      assertEquals(16, first.length);
      assertArrayEquals(first, cmac.sign(master, new byte[16]));

      Pkcs11Config otherToken = master.copy();
      otherToken.tokenLabel = label + "x";
      assertThrows(IllegalArgumentException.class, () -> cmac.sign(otherToken, new byte[16]));
      handle = session.token().sessionHandle();
    }
    assertEquals(1, recorder.opened.size());
    assertEquals(1, recorder.logins);
    assertEquals(Pkcs11Constants.CKR_SESSION_HANDLE_INVALID, sessionInfo(library, handle));
  }

  @Test
  void ensureRootSignerIsIdempotentAndAddsSki() throws Exception {
    Pkcs11AdminService admin = new Pkcs11AdminService();
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      Pkcs11AdminService.RootSigner generated =
          admin.ensureRootSigner(session, "root", "CN=Idempotent Root", 7300);
      assertEquals(Pkcs11AdminService.RootSigner.Outcome.KEY_GENERATED, generated.outcome);
      X509Certificate certificate = generated.certificate;
      assertArrayEquals(
          KeyIdentifiers.ski(certificate.getPublicKey()),
          org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(
                  org.bouncycastle.asn1.ASN1OctetString.getInstance(
                          certificate.getExtensionValue("2.5.29.14"))
                      .getOctets())
              .getKeyIdentifier());
      assertEquals(Integer.MAX_VALUE, certificate.getBasicConstraints());
      assertTrue(certificate.getCriticalExtensionOIDs().contains("2.5.29.19"));
      assertTrue(certificate.getCriticalExtensionOIDs().contains("2.5.29.15"));
      assertArrayEquals(
          new boolean[] {false, false, false, false, false, true, true, false, false},
          certificate.getKeyUsage());
      assertTrue(certificate.getSerialNumber().signum() > 0);
      assertTrue(certificate.getSerialNumber().bitLength() <= 128);
      long days =
          (certificate.getNotAfter().getTime() - certificate.getNotBefore().getTime())
              / (24L * 60L * 60L * 1000L);
      assertEquals(7300, days);

      Pkcs11AdminService.RootSigner again =
          admin.ensureRootSigner(session, "root", "CN=Idempotent Root", 7300);
      assertEquals(Pkcs11AdminService.RootSigner.Outcome.EXISTING, again.outcome);
      assertArrayEquals(certificate.getEncoded(), again.certificate.getEncoded());
      assertArrayEquals(generated.keyId(), again.keyId());
      assertEquals(1, session.token().findEcPrivateKeys("root").size());

      assertThrows(
          IllegalStateException.class,
          () -> admin.ensureRootSigner(session, "root", "CN=Another Subject", 7300));

      for (NativeLong object : session.token().findCertificates(generated.keyId())) {
        session.token().destroyObject(object);
      }
      Pkcs11AdminService.RootSigner recreated =
          admin.ensureRootSigner(session, "root", "CN=Idempotent Root", 7300);
      assertEquals(Pkcs11AdminService.RootSigner.Outcome.CERTIFICATE_CREATED, recreated.outcome);
      assertArrayEquals(generated.keyId(), recreated.keyId());
      assertArrayEquals(
          certificate.getPublicKey().getEncoded(),
          recreated.certificate.getPublicKey().getEncoded());
      assertEquals(1, session.token().findCertificates(generated.keyId()).size());

      session.token().generateEcP256KeyPair("root", new byte[] {1, 2, 3});
      assertThrows(
          IllegalStateException.class,
          () -> admin.ensureRootSigner(session, "root", "CN=Idempotent Root", 7300));
    }
  }

  @Test
  void legacyRootCertificateIsRefusedUntilReissued() throws Exception {
    Pkcs11AdminService admin = new Pkcs11AdminService();
    try (Pkcs11Session session = Pkcs11Session.open(config)) {
      byte[] id = {0x0A, 0x0B};
      Pkcs11Token token = session.token();
      token.generateEcP256KeyPair("legacy", id);
      X509Certificate legacy = foreignSignedCertificate(token.publicKey("legacy", id));
      token.createCertificate(
          "legacy",
          id,
          legacy.getSubjectX500Principal().getEncoded(),
          legacy.getIssuerX500Principal().getEncoded(),
          new ASN1Integer(legacy.getSerialNumber()).getEncoded(),
          legacy.getEncoded());

      IllegalStateException refused =
          assertThrows(
              IllegalStateException.class,
              () -> admin.ensureRootSigner(session, "legacy", null, 7300));
      assertTrue(refused.getMessage().contains("reissue-certificate"), refused.getMessage());

      Pkcs11AdminService.RootSigner reissued =
          admin.reissueRootCertificate(session, "legacy", null, 365);
      assertEquals(Pkcs11AdminService.RootSigner.Outcome.CERTIFICATE_REISSUED, reissued.outcome);
      assertArrayEquals(id, reissued.keyId());
      assertArrayEquals(
          legacy.getSubjectX500Principal().getEncoded(),
          reissued.certificate.getSubjectX500Principal().getEncoded());
      assertEquals(1, token.findCertificates(id).size());
      assertEquals(
          Pkcs11AdminService.RootSigner.Outcome.EXISTING,
          admin.ensureRootSigner(session, "legacy", null, 7300).outcome);
    }
  }

  private Path pinFile(String name, byte[] pin) throws Exception {
    return SecureFiles.writeNew(temp.resolve(name), pin);
  }

  /** A CA-shaped certificate for {@code publicKey}, signed by an unrelated software key. */
  private static X509Certificate foreignSignedCertificate(java.security.PublicKey publicKey)
      throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair foreign = generator.generateKeyPair();
    X500Name subject = new X500Name("CN=Legacy Root");
    Date now = new Date();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.ONE,
            now,
            new Date(now.getTime() + 86_400_000L),
            subject,
            publicKey);
    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(foreign.getPrivate())));
  }

  private static long sessionInfo(CryptokiLibrary library, NativeLong session) {
    return library.C_GetSessionInfo(session, new Pkcs11Structs.SessionInfo()).longValue()
        & 0xFFFFFFFFL;
  }

  /** Delegates to the real module and records every session handle C_OpenSession returns. */
  private static final class SessionRecorder {
    private final CryptokiLibrary delegate;
    final List<NativeLong> opened = new ArrayList<NativeLong>();
    int logins;

    SessionRecorder(CryptokiLibrary delegate) {
      this.delegate = delegate;
    }

    CryptokiLibrary library() {
      return (CryptokiLibrary)
          Proxy.newProxyInstance(
              CryptokiLibrary.class.getClassLoader(),
              new Class<?>[] {CryptokiLibrary.class},
              (proxy, method, args) -> {
                Object result;
                try {
                  result = method.invoke(delegate, args);
                } catch (InvocationTargetException e) {
                  throw e.getCause();
                }
                if ("C_OpenSession".equals(method.getName())) {
                  opened.add(((NativeLongByReference) args[4]).getValue());
                }
                if ("C_Login".equals(method.getName())) {
                  logins++;
                }
                return result;
              });
    }
  }
}
