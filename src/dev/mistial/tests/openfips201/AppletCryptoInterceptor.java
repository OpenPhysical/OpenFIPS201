package dev.mistial.tests.openfips201;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javacard.framework.Applet;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

/**
 * Fault injection into the cryptographic engines of an installed OpenFIPS201 instance.
 *
 * <p>The applet constructor creates one {@code PIVCrypto} instance and passes it to every object
 * that needs it. {@link #intercept} replaces each of those references, throughout the applet's
 * object graph, with a Mockito spy of that instance whose default answer decides every call; {@link
 * AutoCloseable#close()} puts the original instance back. The class is resolved in the class loader
 * that loaded the installed applet, so the interception reaches the code jCardEngine runs.
 *
 * <p>Objects the applet creates while the interception is active (for example a key defined by a
 * command) keep the spy after it is closed, so tests define their keys before intercepting.
 */
public final class AppletCryptoInterceptor {
  private static final String APPLET_PACKAGE = "com.makina.security.openfips201.";
  private static final String PIV_CRYPTO = APPLET_PACKAGE + "PIVCrypto";
  private static final String OPENFIPS201 = APPLET_PACKAGE + "OpenFIPS201";

  private AppletCryptoInterceptor() {}

  /** Returns the applet instance behind a jCardEngine applet proxy. */
  public static Applet unwrap(Applet proxy) throws Exception {
    if (proxy.getClass().getName().equals(OPENFIPS201)) return proxy;
    for (Field proxyField : proxy.getClass().getDeclaredFields()) {
      if (!InvocationHandler.class.isAssignableFrom(proxyField.getType())) continue;
      proxyField.setAccessible(true);
      Object handler = proxyField.get(null);
      for (Field handlerField : handler.getClass().getDeclaredFields()) {
        handlerField.setAccessible(true);
        Object value = handlerField.get(handler);
        if (value instanceof Applet && value.getClass().getName().equals(OPENFIPS201)) {
          return (Applet) value;
        }
      }
    }
    throw new IllegalStateException("Unable to unwrap simulator applet proxy");
  }

  /**
   * Routes every call on the applet instance's {@code PIVCrypto} through {@code answer} until the
   * returned handle is closed. The answer may call {@code invocation.callRealMethod()} to run the
   * real operation.
   *
   * @param applet the applet instance, as returned by {@link #unwrap}
   * @param answer decides each intercepted call
   * @return a handle whose {@code close()} restores the original engines
   */
  public static AutoCloseable intercept(Applet applet, Answer<?> answer) throws Exception {
    List<Reference> references = new ArrayList<>();
    collect(applet, new IdentityHashMap<Object, Boolean>(), references);
    if (references.isEmpty()) throw new IllegalStateException("No PIVCrypto reference found");
    final Object original = references.get(0).get();
    for (Reference reference : references) {
      if (reference.get() != original) {
        throw new IllegalStateException("The applet instance holds more than one PIVCrypto");
      }
    }
    Object spy =
        Mockito.mock(
            original.getClass(),
            Mockito.withSettings().spiedInstance(original).defaultAnswer(answer));
    for (Reference reference : references) reference.set(spy);
    final List<Reference> restore = references;
    return () -> {
      for (Reference reference : restore) reference.set(original);
    };
  }

  /**
   * Returns the distinct objects of the named applet class reachable from the applet instance.
   *
   * @param applet the applet instance, as returned by {@link #unwrap}
   * @param simpleName the class name without the package, for example {@code "TLVReader"}, or null
   *     for every applet-package object
   */
  public static List<Object> reachable(Applet applet, String simpleName) throws Exception {
    List<Object> result = new ArrayList<>();
    for (Object node : graph(applet)) {
      if (simpleName == null || node.getClass().getName().equals(APPLET_PACKAGE + simpleName)) {
        result.add(node);
      }
    }
    return result;
  }

  /** Returns every applet-package object and object array reachable from {@code root}. */
  private static List<Object> graph(Object root) throws IllegalAccessException {
    Map<Object, Boolean> visited = new IdentityHashMap<>();
    List<Object> pending = new ArrayList<>();
    List<Object> nodes = new ArrayList<>();
    pending.add(root);
    while (!pending.isEmpty()) {
      Object node = pending.remove(pending.size() - 1);
      if (node == null || visited.put(node, Boolean.TRUE) != null) continue;
      Class<?> type = node.getClass();
      if (type.isArray()) {
        if (type.getComponentType().isPrimitive()) continue;
        for (Object element : (Object[]) node) pending.add(element);
        continue;
      }
      if (!type.getName().startsWith(APPLET_PACKAGE)) continue;
      nodes.add(node);
      for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
        for (Field field : c.getDeclaredFields()) {
          if (Modifier.isStatic(field.getModifiers()) || field.getType().isPrimitive()) continue;
          field.setAccessible(true);
          pending.add(field.get(node));
        }
      }
    }
    return nodes;
  }

  /** Records every field and array slot that references a {@code PIVCrypto}. */
  private static void collect(Object node, Map<Object, Boolean> visited, List<Reference> found)
      throws IllegalAccessException {
    if (node == null || visited.put(node, Boolean.TRUE) != null) return;
    Class<?> type = node.getClass();
    if (type.isArray()) {
      if (type.getComponentType().isPrimitive()) return;
      Object[] array = (Object[]) node;
      for (int i = 0; i < array.length; i++) {
        Object value = array[i];
        if (isCrypto(value)) {
          found.add(new Reference(array, i));
        } else {
          collect(value, visited, found);
        }
      }
      return;
    }
    if (!type.getName().startsWith(APPLET_PACKAGE)) return;
    for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
      for (Field field : c.getDeclaredFields()) {
        if (Modifier.isStatic(field.getModifiers()) || field.getType().isPrimitive()) continue;
        field.setAccessible(true);
        Object value = field.get(node);
        if (isCrypto(value)) {
          found.add(new Reference(node, field));
        } else {
          collect(value, visited, found);
        }
      }
    }
  }

  private static boolean isCrypto(Object value) {
    return value != null && value.getClass().getName().equals(PIV_CRYPTO);
  }

  /** One field or array slot holding the engines. */
  private static final class Reference {
    private final Object holder;
    private final Field field;
    private final int index;

    Reference(Object holder, Field field) {
      this.holder = holder;
      this.field = field;
      this.index = -1;
    }

    Reference(Object[] holder, int index) {
      this.holder = holder;
      this.field = null;
      this.index = index;
    }

    Object get() throws IllegalAccessException {
      return field == null ? ((Object[]) holder)[index] : field.get(holder);
    }

    void set(Object value) throws IllegalAccessException {
      if (field == null) {
        ((Object[]) holder)[index] = value;
      } else {
        field.set(holder, value);
      }
    }
  }
}
