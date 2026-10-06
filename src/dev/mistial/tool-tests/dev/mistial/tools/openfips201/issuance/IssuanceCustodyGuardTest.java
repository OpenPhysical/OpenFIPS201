/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.common.CardTarget;
import org.junit.jupiter.api.Test;

/**
 * Development custody (softhsm-dev) is confined to emulated targets: a production station refuses a
 * {@code pcsc:} card unless {@code --allow-dev-custody} is given and a {@code pcsc:} SAM always; a
 * root station refuses a {@code pcsc:} SAM.
 */
class IssuanceCustodyGuardTest {
  private static final CardTarget PCSC = CardTarget.parse("pcsc:Reader 0");
  private static final CardTarget ZMQ = CardTarget.parse("zmq:tcp://127.0.0.1:5555");

  private static IssuanceTestKeys.LocalRoot root(boolean development) {
    IssuanceTestKeys.LocalRoot root = new IssuanceTestKeys.LocalRoot();
    root.development = development;
    return root;
  }

  private static IssuanceTestKeys.LocalCustody custody(boolean development) {
    IssuanceTestKeys.LocalCustody custody =
        new IssuanceTestKeys.LocalCustody(root(false).rootCertificate());
    custody.development = development;
    return custody;
  }

  @Test
  void developmentCustodyRefusesAPcscTargetWithoutTheOverride() {
    IllegalArgumentException refused =
        assertThrows(
            IllegalArgumentException.class,
            () -> IssuanceService.requireCustody(custody(true), PCSC, false));
    assertTrue(refused.getMessage().contains("--allow-dev-custody"), refused.getMessage());
  }

  @Test
  void developmentCustodyAllowsAnEmulatedTarget() {
    assertDoesNotThrow(() -> IssuanceService.requireCustody(custody(true), ZMQ, false));
  }

  @Test
  void allowDevCustodyPermitsAPcscCard() {
    assertDoesNotThrow(() -> IssuanceService.requireCustody(custody(true), PCSC, true));
  }

  @Test
  void productionCustodyIsNotRestricted() {
    assertDoesNotThrow(() -> IssuanceService.requireCustody(custody(false), PCSC, false));
    assertDoesNotThrow(() -> IssuanceService.requireCustody(custody(false), ZMQ, false));
  }

  @Test
  void developmentRootCustodyRefusesAPcscSamAndHasNoOverride() {
    IllegalArgumentException refused =
        assertThrows(
            IllegalArgumentException.class,
            () -> IssuanceService.requireRootCustody(root(true), PCSC));
    assertTrue(refused.getMessage().contains("softhsm-dev"), refused.getMessage());
    assertDoesNotThrow(() -> IssuanceService.requireRootCustody(root(true), ZMQ));
    assertDoesNotThrow(() -> IssuanceService.requireRootCustody(root(false), PCSC));
  }

  @Test
  void samPersonalizationChecksRootCustodyBeforeAnythingElse() {
    IssuanceService.PersonalizeRequest request = new IssuanceService.PersonalizeRequest();
    request.sam = PCSC;
    IllegalArgumentException refused =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IssuanceService().personalize(request, root(true), "CN=unused"));
    assertTrue(refused.getMessage().contains("pcsc: SAM"), refused.getMessage());
  }

  @Test
  void samReceiveRefusesAPcscSamUnderDevelopmentCustodyWithoutOverride() {
    // 'sam receive' has no --allow-dev-custody: a development station never receives a physical
    // SAM.
    IllegalArgumentException refused =
        assertThrows(
            IllegalArgumentException.class,
            () -> new IssuanceService().receive("unused", PCSC, null, null, null, custody(true)));
    assertTrue(refused.getMessage().contains("softhsm-dev"), refused.getMessage());
  }
}
