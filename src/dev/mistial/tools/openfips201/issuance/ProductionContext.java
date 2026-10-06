/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.Gson;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.gp.IssuerCardKeyService;
import dev.mistial.tools.openfips201.gp.Scp03Kdf3DerivationService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AdminService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11AesCmacService;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11KeyTransport;
import dev.mistial.tools.openfips201.pkcs11.Pkcs11Session;
import dev.mistial.tools.openfips201.producer.ProducerPaths;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.producer.StationGuard;
import dev.mistial.tools.openfips201.profiles.IssuerProfile;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;

/**
 * The production station's PKCS#11 custody for one command: the card-master key and the station
 * handoff ECDH key ({@code <producer>-station-handoff}) on the production token, and the public
 * {@code root.pem}. Loading refuses a producer that is not a production station.
 */
public final class ProductionContext implements Custody, AutoCloseable {
  private static final Gson GSON = new Gson();

  public final String name;
  public final IssuerProfile profile;
  private final String custody;
  private final X509Certificate rootCertificate;
  private Pkcs11Session session;

  private ProductionContext(
      String name, IssuerProfile profile, String custody, X509Certificate rootCertificate) {
    this.name = name;
    this.profile = profile;
    this.custody = custody;
    this.rootCertificate = rootCertificate;
  }

  public static ProductionContext load(String name) throws Exception {
    StationGuard.requireStation(name, ProducerSetupService.STATION_PRODUCTION);
    String json =
        new String(Files.readAllBytes(ProducerPaths.producerProfile(name)), StandardCharsets.UTF_8);
    IssuerProfile profile = GSON.fromJson(json, IssuerProfile.class);
    String custody =
        com.google.gson.JsonParser.parseString(json).getAsJsonObject().get("custody").getAsString();
    X509Certificate root =
        StationGuard.readRootPem(ProducerPaths.producer(name).resolve("root.pem"));
    return new ProductionContext(name, profile, custody, root);
  }

  /** Token label of the station handoff key. */
  public static String handoffKeyLabel(String producer) {
    return producer + "-station-handoff";
  }

  private Pkcs11Session session() {
    if (session == null) {
      session = Pkcs11Session.open(profile.cardKeys.pkcs11);
    }
    return session;
  }

  @Override
  public X509Certificate rootCertificate() {
    return rootCertificate;
  }

  @Override
  public ScpKeyDeriver keyDeriver() {
    final IssuerCardKeyService keys = new IssuerCardKeyService();
    return new ScpKeyDeriver() {
      @Override
      public DerivedScpKeys derive(byte[] kdd) {
        return new Scp03Kdf3DerivationService(new Pkcs11AesCmacService(session()))
            .derive(
                keys.cardMasterKey(profile),
                kdd,
                profile.cardKeys.newKeyVersion,
                profile.cardKeys.keyLengthBytes);
      }

      @Override
      public String description() {
        return "pkcs11:" + keys.describeCardMasterKey(profile);
      }
    };
  }

  @Override
  public byte[] stationPoint() {
    return new Pkcs11AdminService().ensureEcdhKey(session(), handoffKeyLabel(name));
  }

  @Override
  public byte[] unwrapHandoff(byte[] ephemeralPub, byte[] wrapped, byte[] sharedInfo) {
    return new Pkcs11KeyTransport(session(), isDevelopment())
        .unwrapBytesFrom(handoffKeyLabel(name), ephemeralPub, wrapped, sharedInfo);
  }

  @Override
  public void requireProductionClean(String producer) throws IOException {
    StationGuard.requireProductionClean(producer, session(), rootCertificate);
  }

  @Override
  public String custody() {
    return custody;
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
