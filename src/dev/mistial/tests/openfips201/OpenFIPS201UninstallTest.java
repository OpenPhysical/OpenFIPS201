package dev.mistial.tests.openfips201;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.tools.openfips201.provisioning.StandardCardProfile;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * The applet instance owns its cryptographic engines and codecs: the constructor allocates them at
 * install and passes them to their users, and no static field references them.
 *
 * <p>JCRE 3.0.5 Section 11.3.4.2 refuses deleting an applet instance when "An object owned by the
 * applet instance is referenced from a static field on any package on the card", so uninstall() has
 * nothing to release. JC 3.0.5 API AppletEvent states "The Java Card runtime environment will not
 * rollback state automatically if applet deletion fails"; an instance whose uninstall() ran but
 * whose deletion did not complete therefore keeps working with the objects it allocated at install.
 * A second instance of the package owns separate objects and shares no mutable state.
 */
class OpenFIPS201UninstallTest extends OpenFIPS201TestSupport {
  private static final byte[] SECOND_AID_BYTES = hex("A00000030800001000010002");
  private static final AID SECOND_AID =
      new AID(SECOND_AID_BYTES, (short) 0, (byte) SECOND_AID_BYTES.length);
  private static final String[] SHARED_SERVICES = {
    "PIVCrypto", "TLVReader", "TLVWriter", "DERWriter"
  };

  @Test
  void failedDeletionLeavesTheInstanceOperationalWithoutAllocating() throws Exception {
    assertOperational("before uninstall");
    Applet applet = AppletCryptoInterceptor.unwrap(engine.getApplet(OPENFIPS201_AID));
    List<Object> services = sharedServices(applet);

    try (Allocations allocations = new Allocations()) {
      try (AutoCloseable ignored = enterEngineContext()) {
        ((AppletEvent) engine.getApplet(OPENFIPS201_AID)).uninstall();
      }
      assertOperational("after an uninstall whose deletion did not complete");
      assertEquals(
          Collections.emptyList(),
          allocations.recorded(),
          "uninstall() and the commands after it allocate nothing");
    }

    List<Object> after = sharedServices(applet);
    assertEquals(services.size(), after.size(), "The same shared services remain reachable");
    for (int i = 0; i < services.size(); i++) {
      assertTrue(services.get(i) == after.get(i), "uninstall() keeps " + services.get(i));
    }
  }

  @Test
  void noStaticFieldReferencesAnAllocatedObject() throws Exception {
    Applet applet = AppletCryptoInterceptor.unwrap(engine.getApplet(OPENFIPS201_AID));
    Set<Class<?>> classes = new LinkedHashSet<>();
    for (Object node : AppletCryptoInterceptor.reachable(applet, null))
      classes.add(node.getClass());
    ClassLoader loader = applet.getClass().getClassLoader();
    for (String name : SHARED_SERVICES) {
      classes.add(Class.forName("com.makina.security.openfips201." + name, false, loader));
    }
    classes.add(Class.forName("com.makina.security.openfips201.TLV", false, loader));

    for (Class<?> type : classes) {
      for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
        for (Field field : c.getDeclaredFields()) {
          int modifiers = field.getModifiers();
          if (!Modifier.isStatic(modifiers) || field.isSynthetic()) continue;
          Class<?> fieldType = field.getType();
          boolean constant =
              Modifier.isFinal(modifiers)
                  && (fieldType.isPrimitive()
                      || (fieldType.isArray() && fieldType.getComponentType().isPrimitive()));
          assertTrue(constant, c.getSimpleName() + "." + field.getName() + " is not a constant");
        }
      }
    }
  }

  @Test
  void secondInstanceSharesNoServiceWithTheFirst() throws Exception {
    try (Allocations allocations = new Allocations()) {
      engine.installApplet(
          SECOND_AID, com.makina.security.openfips201.OpenFIPS201.class, new byte[0]);
      assertFalse(
          allocations.recorded().isEmpty(), "Installing an instance allocates its own services");
    }
    Applet first = AppletCryptoInterceptor.unwrap(engine.getApplet(OPENFIPS201_AID));
    Applet second = AppletCryptoInterceptor.unwrap(engine.getApplet(SECOND_AID));
    assertFalse(first == second, "Two instances");

    Map<Object, Boolean> firstServices = new IdentityHashMap<>();
    for (Object service : sharedServices(first)) firstServices.put(service, Boolean.TRUE);
    List<Object> secondServices = sharedServices(second);
    assertEquals(firstServices.size(), secondServices.size(), "Each instance owns every service");
    for (Object service : secondServices) {
      assertFalse(
          firstServices.containsKey(service),
          "The second instance must not reach the first instance's "
              + service.getClass().getSimpleName());
    }

    // Engines that fail every operation in the second instance leave the first one unaffected.
    assertSw(0x9000, selectSecond(), "SELECT the second instance");
    try (AutoCloseable broken =
        AppletCryptoInterceptor.intercept(
            second,
            invocation -> {
              throw new CryptoException(CryptoException.ILLEGAL_USE);
            })) {
      assertOperational("while the second instance's engines fail");
    }
    assertSw(0x9000, selectSecond(), "SELECT the second instance again");
  }

  @Test
  void deletingAnotherInstanceLeavesThisInstanceOperational() {
    engine.installApplet(
        SECOND_AID, com.makina.security.openfips201.OpenFIPS201.class, new byte[0]);
    engine.deleteApplet(SECOND_AID);

    assertOperational("after deleting a second instance of the package");
  }

  /**
   * Exercises the random-number engine, the TLV codecs and the AES engine (9B challenge-response),
   * and PIN verification.
   */
  private void assertOperational(String context) {
    ResponseAPDU response =
        authenticateCardManagementKeyResponse(
            StandardCardProfile.ADMIN_KEY_ALG, StandardCardProfile.ADMIN_KEY);
    assertSw(0x9000, response, "9B challenge-response authentication " + context);
    assertSw(
        0x9000, transmit(0x00, 0x20, 0x00, 0x80, StandardCardProfile.PIN), "VERIFY " + context);
  }

  private ResponseAPDU selectSecond() {
    return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, SECOND_AID_BYTES, 0));
  }

  /** The instance's engines and codecs, in a stable order. */
  private static List<Object> sharedServices(Applet applet) throws Exception {
    List<Object> services = new ArrayList<>();
    for (String name : SHARED_SERVICES) {
      List<Object> instances = AppletCryptoInterceptor.reachable(applet, name);
      if (!name.equals("DERWriter") || isAttestationEnabledBuild()) {
        assertFalse(instances.isEmpty(), name + " must be allocated at install");
      }
      services.addAll(instances);
    }
    return services;
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    return (AutoCloseable) asCurrent.invoke(engine);
  }

  /**
   * Records every allocation the Java Card API offers an applet: transient arrays, keys, and
   * cryptographic engines. Each call still runs the real implementation.
   */
  private static final class Allocations implements AutoCloseable {
    private final List<String> recorded = Collections.synchronizedList(new ArrayList<String>());
    private final List<MockedStatic<?>> mocks = new ArrayList<>();

    Allocations() {
      record(JCSystem.class, "makeTransient", "makeGlobalArray");
      record(KeyBuilder.class, "buildKey");
      record(Cipher.class, "getInstance");
      record(Signature.class, "getInstance");
      record(MessageDigest.class, "getInstance");
      record(KeyAgreement.class, "getInstance");
      record(RandomData.class, "getInstance");
    }

    private void record(final Class<?> api, final String... prefixes) {
      mocks.add(
          Mockito.mockStatic(
              api,
              invocation -> {
                String method = invocation.getMethod().getName();
                for (String prefix : prefixes) {
                  if (method.startsWith(prefix)) {
                    recorded.add(api.getSimpleName() + "." + method);
                  }
                }
                return invocation.callRealMethod();
              }));
    }

    List<String> recorded() {
      return new ArrayList<>(recorded);
    }

    @Override
    public void close() {
      for (int i = mocks.size() - 1; i >= 0; i--) mocks.get(i).close();
    }
  }
}
