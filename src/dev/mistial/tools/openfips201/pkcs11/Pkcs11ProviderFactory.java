/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

final class Pkcs11ProviderFactory {
  private Pkcs11ProviderFactory() {}

  static Provider create(String name, Pkcs11Config config) throws Exception {
    StringBuilder text = new StringBuilder();
    text.append("name=").append(name).append('\n');
    text.append("library=").append(config.module).append('\n');
    if (config.slot != null) {
      text.append("slot=").append(config.slot.intValue()).append('\n');
    }

    Class<?> clazz = Class.forName("sun.security.pkcs11.SunPKCS11");
    byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
    try {
      Constructor<?> constructor = clazz.getConstructor(java.io.InputStream.class);
      Provider provider =
          (Provider) constructor.newInstance(new ByteArrayInputStream(bytes));
      Security.addProvider(provider);
      return provider;
    } catch (NoSuchMethodException ignored) {
      Provider base = Security.getProvider("SunPKCS11");
      if (base == null) {
        base = (Provider) clazz.getConstructor().newInstance();
      }
      Path configFile = Files.createTempFile("openfips201-pkcs11-", ".cfg");
      Files.write(configFile, text.toString().getBytes(StandardCharsets.UTF_8));
      configFile.toFile().deleteOnExit();
      Method configure = Provider.class.getMethod("configure", String.class);
      Provider provider = (Provider) configure.invoke(base, configFile.toString());
      Security.addProvider(provider);
      return provider;
    }
  }
}
