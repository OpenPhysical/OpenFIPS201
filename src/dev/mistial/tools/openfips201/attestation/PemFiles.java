/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

final class PemFiles {
  private PemFiles() {}

  static void writePrivateKey(Path path, PrivateKey privateKey, char[] passphrase)
      throws Exception {
    AttestationSupport.ensureProvider();
    try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.US_ASCII);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      if (passphrase == null || passphrase.length == 0) {
        pemWriter.writeObject(privateKey);
      } else {
        JceOpenSSLPKCS8EncryptorBuilder builder =
            new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setIterationCount(100_000)
                .setPassword(passphrase);
        OutputEncryptor encryptor = builder.build();
        pemWriter.writeObject(new JcaPKCS8Generator(privateKey, encryptor));
      }
    }
  }

  static void writeObject(Path path, Object object) throws IOException {
    try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.US_ASCII);
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(object);
    }
  }

  static PrivateKey readPrivateKey(Path path, char[] passphrase) throws Exception {
    AttestationSupport.ensureProvider();
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
        PEMParser parser = new PEMParser(reader)) {
      Object object = parser.readObject();
      JcaPEMKeyConverter converter =
          new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
      if (object instanceof PEMKeyPair) {
        return converter.getKeyPair((PEMKeyPair) object).getPrivate();
      }
      if (object instanceof PrivateKeyInfo) {
        return converter.getPrivateKey((PrivateKeyInfo) object);
      }
      if (object instanceof PEMEncryptedKeyPair) {
        requirePassphrase(passphrase, path);
        return converter
            .getKeyPair(
                ((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(
                        new JcePEMDecryptorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(passphrase)))
            .getPrivate();
      }
      if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
        requirePassphrase(passphrase, path);
        return converter.getPrivateKey(
            ((PKCS8EncryptedPrivateKeyInfo) object)
                .decryptPrivateKeyInfo(
                    new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(passphrase)));
      }
      throw new IOException("Unsupported private key PEM object in " + path);
    }
  }

  static X509Certificate readCertificate(Path path) throws Exception {
    AttestationSupport.ensureProvider();
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
        PEMParser parser = new PEMParser(reader)) {
      Object object = parser.readObject();
      if (!(object instanceof X509CertificateHolder)) {
        throw new IOException("Expected an X.509 certificate PEM in " + path);
      }
      return new JcaX509CertificateConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCertificate((X509CertificateHolder) object);
    }
  }

  private static void requirePassphrase(char[] passphrase, Path path) throws IOException {
    if (passphrase == null || passphrase.length == 0) {
      throw new IOException("Private key is encrypted and needs a passphrase: " + path);
    }
  }
}
