package com.makina.security.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pro.javacard.engine.JavaCardEngine;

/** White-box tests of the F9 authority lifecycle in {@link PIVAttestation}. */
class PIVAttestationStateTest {

  private static final byte PERSONALIZED = (byte) 0x0F;

  private final JavaCardEngine engine = JavaCardEngine.create();
  private AutoCloseable context;
  private MockedStatic<GPSystem> gpSystem;

  @BeforeEach
  void enterEngine() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    context = (AutoCloseable) asCurrent.invoke(engine);
    PIVCrypto.init();
    gpSystem = Mockito.mockStatic(GPSystem.class);
    gpSystem.when(GPSystem::getCardContentState).thenReturn(GPSystem.APPLICATION_SELECTABLE);
  }

  @AfterEach
  void leaveEngine() throws Exception {
    gpSystem.close();
    context.close();
  }

  @Test
  void lifecycleMovesThroughGeneratedActivatingAndActive() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    assertEquals(PIVAttestation.STATE_NONE, attestation.getAuthorityState());
    attestation.requireAuthorityProvisionable();

    attestation.beginAuthorityGeneration();
    assertEquals(PIVAttestation.STATE_NONE, attestation.getAuthorityState());
    attestation.completeAuthorityGeneration();
    assertEquals(PIVAttestation.STATE_GENERATED, attestation.getAuthorityState());
    attestation.requireAuthorityProvisionable();

    setState(attestation, PIVAttestation.STATE_ACTIVATING);
    assertTrue(attestation.isAuthorityActivationPending());
    assertFalse(attestation.isAuthorityActive());
    assertConditionsNotSatisfied(attestation::requireAuthorityProvisionable);

    attestation.completeAuthorityActivation();
    assertFalse(attestation.isAuthorityActivationPending());
    assertTrue(attestation.isAuthorityActive());
    assertConditionsNotSatisfied(attestation::requireAuthorityProvisionable);
  }

  @Test
  void regenerationDiscardsStoredProfile() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    attestation.completeAuthorityGeneration();
    setShort(attestation, "certificateLength", (short) 0x200);
    setShort(attestation, "opidLength", (short) 18);

    attestation.beginAuthorityGeneration();
    assertEquals(PIVAttestation.STATE_NONE, attestation.getAuthorityState());
    assertEquals((short) 0, attestation.getCertificateLength());
    assertEquals((short) 0, attestation.getAuthorityContainerLength());
    assertEquals((short) 0, attestation.getOpidLength());
  }

  @Test
  void personalizedApplicationIsNotProvisionable() {
    PIVAttestation attestation = new PIVAttestation();
    gpSystem.when(GPSystem::getCardContentState).thenReturn(PERSONALIZED);
    assertConditionsNotSatisfied(attestation::requireAuthorityProvisionable);
  }

  @Test
  void proofAndLoadRequireGeneratedAuthority() {
    PIVAttestation attestation = new PIVAttestation();
    PIVKeyObjectECC authority = authority();
    byte[] scratch = new byte[0x100];
    assertConditionsNotSatisfied(
        () ->
            attestation.signPossessionProof(
                authority, new byte[32], (short) 0, (short) 32, scratch));
    assertConditionsNotSatisfied(
        () ->
            attestation.loadAuthorityCertificate(
                authority, new byte[0x200], (short) 0, (short) 0x200));

    // Generated material without the GENERATED state is still refused.
    authority.generate(scratch, (short) 0);
    authority.markGenerated();
    assertConditionsNotSatisfied(
        () ->
            attestation.signPossessionProof(
                authority, new byte[32], (short) 0, (short) 32, scratch));
  }

  @Test
  void possessionProofSignsDomainSeparatedMessageAndZeroisesWorkspace() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    PIVKeyObjectECC authority = generatedAuthority(attestation);
    byte[] point = new byte[65];
    authority.getPublicPoint(point, (short) 0);

    byte[] nonce = new byte[64];
    for (int i = 0; i < nonce.length; i++) nonce[i] = (byte) (i * 7);
    byte[] scratch = new byte[0x100];
    Arrays.fill(scratch, (byte) 0x5A);
    short length =
        attestation.signPossessionProof(authority, nonce, (short) 0, (short) nonce.length, scratch);

    for (int i = length; i < 0xF0; i++) {
      assertEquals(0, scratch[i], "workspace octet " + i + " must be zeroised");
    }
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKey(point));
    verifier.update("OPF9POP".getBytes(StandardCharsets.US_ASCII));
    verifier.update(nonce);
    verifier.update(point);
    assertTrue(verifier.verify(Arrays.copyOf(scratch, length)));

    ISOException tooShort =
        assertThrows(
            ISOException.class,
            () ->
                attestation.signPossessionProof(
                    authority, nonce, (short) 0, (short) 15, new byte[0x100]));
    assertEquals(ISO7816.SW_WRONG_LENGTH, tooShort.getReason());
  }

  @Test
  void loadRejectsOversizeCertificateBeforeParsing() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    PIVKeyObjectECC authority = generatedAuthority(attestation);
    ISOException thrown =
        assertThrows(
            ISOException.class,
            () ->
                attestation.loadAuthorityCertificate(
                    authority, new byte[0x2E1], (short) 0, (short) 0x2E1));
    assertEquals(ISO7816.SW_FILE_FULL, thrown.getReason());
    assertEquals(PIVAttestation.STATE_GENERATED, attestation.getAuthorityState());
  }

  @Test
  void attestRejectsRoleWithoutSignOrKeyEstablish() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    PIVKeyObjectECC authority = generatedAuthority(attestation);
    setState(attestation, PIVAttestation.STATE_ACTIVE);

    PIVKeyObjectECC target =
        (PIVKeyObjectECC)
            PIVKeyObject.create(
                (byte) 0x9A,
                PIVObject.ACCESS_MODE_ALWAYS,
                PIVObject.ACCESS_MODE_ALWAYS,
                (byte) 0x00,
                PIV.ID_ALG_ECC_P256,
                PIVKeyObject.ROLE_NONE,
                PIVKeyObject.ATTR_NONE,
                new ECCurveRegistry());
    byte[] scratch = new byte[0x300];
    target.generate(scratch, (short) 0);
    target.markGenerated();

    assertConditionsNotSatisfied(
        () ->
            attestation.buildCertificate(
                authority, target, (byte) 0x9A, scratch, new byte[0x400], (short) 0));
  }

  @Test
  void attestRequiresActiveGeneratedAuthority() throws Exception {
    PIVAttestation attestation = new PIVAttestation();
    PIVKeyObjectECC authority = generatedAuthority(attestation);
    byte[] scratch = new byte[0x300];
    // GENERATED is not ACTIVE.
    assertConditionsNotSatisfied(
        () ->
            attestation.buildCertificate(
                authority, authority, (byte) 0x9A, scratch, new byte[0x400], (short) 0));
  }

  private static PIVKeyObjectECC authority() {
    return (PIVKeyObjectECC)
        PIVKeyObject.create(
            PIV.ID_KEY_ATTESTATION,
            PIVObject.ACCESS_MODE_NEVER,
            PIVObject.ACCESS_MODE_NEVER,
            (byte) 0x00,
            PIV.ID_ALG_ECC_P256,
            PIVKeyObject.ROLE_SIGN,
            PIVKeyObject.ATTR_NONE,
            new ECCurveRegistry());
  }

  private static PIVKeyObjectECC generatedAuthority(PIVAttestation attestation) {
    PIVKeyObjectECC authority = authority();
    attestation.beginAuthorityGeneration();
    authority.generate(new byte[0x100], (short) 0);
    authority.markGenerated();
    attestation.completeAuthorityGeneration();
    return authority;
  }

  private static PublicKey publicKey(byte[] point) throws Exception {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
    ECPoint w =
        new ECPoint(
            new BigInteger(1, Arrays.copyOfRange(point, 1, 33)),
            new BigInteger(1, Arrays.copyOfRange(point, 33, 65)));
    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, spec));
  }

  private static void setState(PIVAttestation attestation, byte state) throws Exception {
    Field field = PIVAttestation.class.getDeclaredField("authorityState");
    field.setAccessible(true);
    field.setByte(attestation, state);
  }

  private static void setShort(PIVAttestation attestation, String name, short value)
      throws Exception {
    Field field = PIVAttestation.class.getDeclaredField(name);
    field.setAccessible(true);
    field.setShort(attestation, value);
  }

  private static void assertConditionsNotSatisfied(ThrowingRunnable runnable) {
    ISOException thrown = assertThrows(ISOException.class, runnable::run);
    assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, thrown.getReason());
  }

  private interface ThrowingRunnable {
    void run();
  }
}
