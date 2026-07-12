/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Enumeration;

public final class Pkcs11SigningKey implements SigningKey {
  private final Provider provider;
  private final String alias;
  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public Pkcs11SigningKey(Pkcs11Config config) throws Exception {
    this.provider = Pkcs11ProviderFactory.create("OpenFIPS201", config);
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    char[] pin = config.readPin();
    try {
      keyStore.load(null, pin);
    } finally {
      java.util.Arrays.fill(pin, '\0');
    }
    this.alias = selectAlias(keyStore, config.keyAlias);
    Key key = keyStore.getKey(alias, null);
    if (!(key instanceof PrivateKey)) {
      throw new IllegalArgumentException("PKCS#11 alias is not a private key: " + alias);
    }
    Certificate certificate = keyStore.getCertificate(alias);
    if (certificate == null) {
      throw new IllegalArgumentException("PKCS#11 alias has no certificate: " + alias);
    }
    this.privateKey = (PrivateKey) key;
    this.publicKey = certificate.getPublicKey();
  }

  @Override
  public PublicKey publicKey() {
    return publicKey;
  }

  @Override
  public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
    byte[] toSign = message;
    String algorithm = jcaAlgorithm;
    if ("SHA256withECDSA".equals(jcaAlgorithm)) {
      toSign = MessageDigest.getInstance("SHA-256").digest(message);
      algorithm = "NONEwithECDSA";
    }
    Signature signer = Signature.getInstance(algorithm, provider);
    signer.initSign(privateKey);
    signer.update(toSign);
    return signer.sign();
  }

  @Override
  public String description() {
    return "pkcs11:" + alias;
  }

  private static String selectAlias(KeyStore keyStore, String requested) throws Exception {
    if (requested != null && !requested.isEmpty()) {
      if (!keyStore.containsAlias(requested)) {
        throw new IllegalArgumentException("PKCS#11 alias was not found: " + requested);
      }
      return requested;
    }
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (keyStore.isKeyEntry(alias)) {
        return alias;
      }
    }
    throw new IllegalArgumentException("PKCS#11 token contains no private-key entries");
  }
}
