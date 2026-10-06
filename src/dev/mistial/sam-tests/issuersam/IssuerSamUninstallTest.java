package dev.mistial.tests.issuersam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.mistial.openphysical.sam.IssuerSam;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.JCSystem;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * The SAM instance owns its DER writer: the constructor allocates it at install and no static field
 * references it, so JCRE 3.0.5 Section 11.3.4.2 does not block deletion and uninstall() releases
 * nothing. JC 3.0.5 API AppletEvent states "The Java Card runtime environment will not rollback
 * state automatically if applet deletion fails"; a SAM whose uninstall() ran but whose deletion did
 * not complete keeps issuing with the objects it allocated at install.
 */
class IssuerSamUninstallTest extends IssuerSamTestSupport {
  private static final byte[] SECOND_SAM_AID_BYTES = hex("F04F50454E50485953414D0002000000");

  @Test
  void failedDeletionLeavesIssuanceOperationalWithoutAllocating() throws Exception {
    Params params = Params.variant(root, 0);
    params.quota = 3;
    personalize(params);
    issueOne();
    Applet sam = unwrap(engine.getApplet(SAM_AID));
    Object writer = field(sam, "certificateWriter");
    assertNotNull(writer, "The DER writer is allocated at install");

    Issued issued;
    try (Allocations allocations = new Allocations()) {
      try (AutoCloseable ignored = enterEngineContext()) {
        ((AppletEvent) engine.getApplet(SAM_AID)).uninstall();
      }
      issued = issueOne();
      assertEquals(
          Collections.emptyList(),
          allocations.recorded(),
          "uninstall() and the issuance after it allocate nothing");
    }
    assertEquals(
        referenceOpid(params, 2),
        IssuerSamIssuanceTest.serialNumberOf(new X509CertificateHolder(issued.certificate)),
        "Issuance continues with the next OPID");
    assertTrue(writer == field(sam, "certificateWriter"), "uninstall() keeps the DER writer");
  }

  @Test
  void noStaticFieldReferencesAnAllocatedObject() throws Exception {
    ClassLoader loader = unwrap(engine.getApplet(SAM_AID)).getClass().getClassLoader();
    for (String name :
        new String[] {
          "IssuerSam", "DERWriter", "TLVReader", "SamLedger", "SamCrypto", "SamState"
        }) {
      Class<?> type = Class.forName("dev.mistial.openphysical.sam." + name, false, loader);
      for (Field field : type.getDeclaredFields()) {
        int modifiers = field.getModifiers();
        if (!Modifier.isStatic(modifiers) || field.isSynthetic()) continue;
        Class<?> fieldType = field.getType();
        boolean constant =
            Modifier.isFinal(modifiers)
                && (fieldType.isPrimitive()
                    || (fieldType.isArray() && fieldType.getComponentType().isPrimitive()));
        assertTrue(constant, name + "." + field.getName() + " is not a constant");
      }
    }
  }

  @Test
  void secondInstanceOwnsItsOwnWriter() throws Exception {
    AID secondAid = new AID(SECOND_SAM_AID_BYTES, (short) 0, (byte) SECOND_SAM_AID_BYTES.length);
    engine.installApplet(secondAid, IssuerSam.class, new byte[0]);
    Object first = field(unwrap(engine.getApplet(SAM_AID)), "certificateWriter");
    Object second = field(unwrap(engine.getApplet(secondAid)), "certificateWriter");
    assertNotNull(second, "The second instance allocates its writer at install");
    assertFalse(first == second, "Instances must not share a DER writer");
  }

  private AutoCloseable enterEngineContext() throws Exception {
    Method asCurrent = engine.getClass().getMethod("asCurrent");
    asCurrent.setAccessible(true);
    return (AutoCloseable) asCurrent.invoke(engine);
  }

  private static Object field(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  /** Returns the SAM instance behind a jCardEngine applet proxy. */
  private static Applet unwrap(Applet proxy) throws Exception {
    String name = IssuerSam.class.getName();
    if (proxy.getClass().getName().equals(name)) return proxy;
    for (Field proxyField : proxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet && value.getClass().getName().equals(name)) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
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
