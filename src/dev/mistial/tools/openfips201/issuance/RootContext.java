/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import dev.mistial.tools.openfips201.crypto.CertifiedSigningKey;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11KeyTransport;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.producer.IinKeyService;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.producer.StationGuard;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * The root station's PKCS#11 custody for one command: the root CA key, the IIN FF1 keys ({@link
 * IinKeyService}) and the registry head (CKO_DATA {@code <producer>-registry-head}) on the root
 * token. Loading refuses a producer that is not a root station.
 */
public final class RootContext implements RootKeys, AutoCloseable {
  static final String REGISTRY_APPLICATION = "openfips201-registry";
  private static final Gson GSON = new Gson();

  public final String name;
  public final IssuerProfile profile;
  private final String custody;
  private final X509Certificate rootCertificate;
  private Pkcs11Session session;

  private RootContext(
      String name, IssuerProfile profile, String custody, X509Certificate rootCertificate) {
    this.name = name;
    this.profile = profile;
    this.custody = custody;
    this.rootCertificate = rootCertificate;
  }

  public static RootContext load(String name) throws Exception {
    StationGuard.requireStation(name, ProducerSetupService.STATION_ROOT);
    String json =
        new String(Files.readAllBytes(ProducerPaths.producerProfile(name)), StandardCharsets.UTF_8);
    IssuerProfile profile = GSON.fromJson(json, IssuerProfile.class);
    String custody =
        com.google.gson.JsonParser.parseString(json).getAsJsonObject().get("custody").getAsString();
    X509Certificate root =
        StationGuard.readRootPem(ProducerPaths.producer(name).resolve("root.pem"));
    return new RootContext(name, profile, custody, root);
  }

  public static String registryHeadLabel(String producer) {
    return producer + "-registry-head";
  }

  private Pkcs11Session session() {
    if (session == null) {
      session = Pkcs11Session.open(profile.pkcs11);
    }
    return session;
  }

  @Override
  public SigningKey rootSigner() throws Exception {
    CertifiedSigningKey signer = CertifiedSigningKey.of(session().signingKey(profile.pkcs11));
    if (!Arrays.equals(signer.certificate().getEncoded(), rootCertificate.getEncoded())) {
      throw new IllegalStateException(
          "The root certificate on the token differs from root.pem; run 'producer root"
              + " reissue-certificate'");
    }
    return signer;
  }

  @Override
  public X509Certificate rootCertificate() {
    return rootCertificate;
  }

  @Override
  public String ensureIinKey(int iin) {
    return new IinKeyService().ensureKey(session(), name, iin);
  }

  @Override
  public OpidCipher iinCipher(int iin) {
    return Pkcs11AdminService.iinCipher(session(), Pkcs11AdminService.iinFpeKeyLabel(name, iin));
  }

  @Override
  public WrappedKey wrapIinKeyForSam(int iin, byte[] samTransportPub) {
    Pkcs11KeyTransport.Wrapped wrapped =
        new Pkcs11KeyTransport(session(), isDevelopment())
            .wrapForSam(Pkcs11AdminService.iinFpeKeyLabel(name, iin), samTransportPub, iin);
    return new WrappedKey(wrapped.ephemeralPublicKey, wrapped.wrappedKey);
  }

  @Override
  public WrappedKey wrapSecret(byte[] secret, byte[] recipientPub, byte[] sharedInfo) {
    Pkcs11KeyTransport.Wrapped wrapped =
        new Pkcs11KeyTransport(session(), isDevelopment())
            .wrapBytesTo(secret, recipientPub, sharedInfo);
    return new WrappedKey(wrapped.ephemeralPublicKey, wrapped.wrappedKey);
  }

  @Override
  public byte[] readRegistryHead() {
    return Pkcs11AdminService.readData(session(), registryHeadLabel(name), REGISTRY_APPLICATION);
  }

  @Override
  public void writeRegistryHead(byte[] head) {
    Pkcs11AdminService.writeData(session(), registryHeadLabel(name), REGISTRY_APPLICATION, head);
  }

  @Override
  public boolean isDevelopment() {
    return ProducerSetupService.CUSTODY_SOFTHSM_DEV.equals(custody);
  }

  @Override
  public void close() {
    if (session != null) {
      session.close();
      session = null;
    }
  }
}
