/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import com.google.gson.JsonObject;
import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.common.ScpConfig;
import dev.mistial.tools.openfips201.common.SecureFiles;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

/**
 * {@code sam-handoff.json} ({@code openfips201.sam-handoff/1}): the root station's delivery of a
 * personalized SAM to one production station, as root-signed canonical JSON ({@link
 * CanonicalJson}).
 *
 * <p>Plaintext members: {@code producer}, {@code iin}, {@code batch}, {@code samId} (hex KDD),
 * {@code quota}, {@code initialTs}, {@code paramsDigest}, {@code f9ValidityDays}, {@code
 * samCertificate} and {@code rootCertificate} (base64 DER), {@code registry} ({@code allocate},
 * {@code bind}: the root-signed registry lines, verbatim), {@code genesis} ({@code entry}, {@code
 * sig}: the SAM's signed genesis entry), and {@code handoff} ({@code station}, {@code stationSki},
 * {@code scpKeyVersion}, {@code ephemeralPublicKey}, {@code wrapped}).
 *
 * <p>Only the handoff SCP keys and the operator PIN are secret. They are wrapped to the station's
 * handoff key (ECDH, X9.63 SHA-256 with SharedInfo {@code "OPSAMHO1" || samId || stationSki}, RFC
 * 3394) as {@link Secret}: {@code enc(16) || mac(16) || dek(16) || pinLength(1) || pin || zero
 * padding} to {@value Secret#LENGTH} octets.
 */
public final class SamHandoff {
  public static final String SCHEMA = "openfips201.sam-handoff/1";

  public final String text;
  public final JsonObject json;

  private SamHandoff(String text, JsonObject json) {
    this.text = text;
    this.json = json;
  }

  /** The secret half of a handoff: SAM SCP keys and operator PIN. */
  public static final class Secret {
    public static final int LENGTH = 72;
    private static final int KEY = 16;
    private final byte[] enc;
    private final byte[] mac;
    private final byte[] dek;
    private final byte[] pin;

    public Secret(byte[] enc, byte[] mac, byte[] dek, byte[] pin) {
      if (enc.length != KEY || mac.length != KEY || dek.length != KEY) {
        throw new IllegalArgumentException("handoff SCP keys are AES-128");
      }
      if (pin.length < 6 || pin.length > 16) {
        throw new IllegalArgumentException("the operator PIN must be 6 to 16 octets");
      }
      this.enc = enc.clone();
      this.mac = mac.clone();
      this.dek = dek.clone();
      this.pin = pin.clone();
    }

    public byte[] encode() {
      byte[] out = new byte[LENGTH];
      System.arraycopy(enc, 0, out, 0, KEY);
      System.arraycopy(mac, 0, out, KEY, KEY);
      System.arraycopy(dek, 0, out, 2 * KEY, KEY);
      out[3 * KEY] = (byte) pin.length;
      System.arraycopy(pin, 0, out, 3 * KEY + 1, pin.length);
      return out;
    }

    public static Secret decode(byte[] encoded) {
      if (encoded == null || encoded.length != LENGTH) {
        throw new IllegalArgumentException("the handoff secret is malformed");
      }
      int pinLength = encoded[3 * KEY] & 0xFF;
      if (pinLength < 6 || pinLength > 16) {
        throw new IllegalArgumentException("the handoff secret is malformed");
      }
      for (int i = 3 * KEY + 1 + pinLength; i < LENGTH; i++) {
        if (encoded[i] != 0) {
          throw new IllegalArgumentException("the handoff secret is malformed");
        }
      }
      return new Secret(
          Arrays.copyOfRange(encoded, 0, KEY),
          Arrays.copyOfRange(encoded, KEY, 2 * KEY),
          Arrays.copyOfRange(encoded, 2 * KEY, 3 * KEY),
          Arrays.copyOfRange(encoded, 3 * KEY + 1, 3 * KEY + 1 + pinLength));
    }

    /** The SCP03 configuration of the handoff keys at {@code keyVersion}. */
    public ScpConfig scp(int keyVersion) {
      return new ScpConfig(ScpConfig.Mode.SCP03, keyVersion, enc, mac, dek);
    }

    public byte[] pin() {
      return pin.clone();
    }

    /** Overwrites every copy this instance holds. */
    public void wipe() {
      Arrays.fill(enc, (byte) 0);
      Arrays.fill(mac, (byte) 0);
      Arrays.fill(dek, (byte) 0);
      Arrays.fill(pin, (byte) 0);
    }
  }

  /** The plaintext fields of a bundle, set by the root station. */
  public static final class Fields {
    public String producer;
    public int iin;
    public int batch;
    public String samId;
    public long quota;
    public long initialTs;
    public byte[] paramsDigest;
    public int f9ValidityDays;
    public byte[] samCertificate;
    public X509Certificate rootCertificate;
    public String allocateLine;
    public String bindLine;
    public SamLedgerEntry.Signed genesis;
    public String station;
    public byte[] stationSki;
    public int scpKeyVersion;
  }

  /** {@code "OPSAMHO1" || samId || stationSki}. */
  public static byte[] sharedInfo(String samId, byte[] stationSki) {
    return EcdhKeyTransport.handoffSharedInfo(HexUtil.parse(samId), stationSki);
  }

  /** Builds and signs a bundle; {@code wrapped} is the secret wrapped to the station. */
  public static SamHandoff sign(Fields fields, RootKeys.WrappedKey wrapped, SigningKey root)
      throws Exception {
    Base64.Encoder base64 = Base64.getEncoder();
    JsonObject document = new JsonObject();
    document.addProperty("schema", SCHEMA);
    document.addProperty("producer", fields.producer);
    document.addProperty("iin", fields.iin);
    document.addProperty("batch", fields.batch);
    document.addProperty("samId", fields.samId);
    document.addProperty("quota", fields.quota);
    document.addProperty("initialTs", fields.initialTs);
    document.addProperty("paramsDigest", HexUtil.format(fields.paramsDigest));
    document.addProperty("f9ValidityDays", fields.f9ValidityDays);
    document.addProperty("samCertificate", base64.encodeToString(fields.samCertificate));
    document.addProperty(
        "rootCertificate", base64.encodeToString(fields.rootCertificate.getEncoded()));
    JsonObject registry = new JsonObject();
    registry.addProperty("allocate", fields.allocateLine);
    registry.addProperty("bind", fields.bindLine);
    document.add("registry", registry);
    JsonObject genesis = new JsonObject();
    genesis.addProperty("entry", HexUtil.format(fields.genesis.entry.encoded()));
    genesis.addProperty("sig", HexUtil.format(fields.genesis.signature()));
    document.add("genesis", genesis);
    JsonObject handoff = new JsonObject();
    handoff.addProperty("station", fields.station);
    handoff.addProperty("stationSki", HexUtil.format(fields.stationSki));
    handoff.addProperty("scpKeyVersion", fields.scpKeyVersion);
    handoff.addProperty("ephemeralPublicKey", HexUtil.format(wrapped.ephemeralPublicKey()));
    handoff.addProperty("wrapped", HexUtil.format(wrapped.wrapped()));
    document.add("handoff", handoff);
    String text = CanonicalJson.sign(document, root);
    return new SamHandoff(text, CanonicalJson.verify(text, root.publicKey()));
  }

  /** Reads a bundle and requires its root signature to verify under {@code root}. */
  public static SamHandoff read(Path file, X509Certificate root) throws IOException {
    String text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8).trim();
    JsonObject json = CanonicalJson.verify(text, root.getPublicKey());
    if (!json.has("schema") || !SCHEMA.equals(json.get("schema").getAsString())) {
      throw new IllegalArgumentException(file + " is not a " + SCHEMA + " bundle");
    }
    SamHandoff bundle = new SamHandoff(text, json);
    if (!Arrays.equals(bundle.rootCertificate(), encoded(root))) {
      throw new IllegalArgumentException("the bundle names a different root certificate");
    }
    return bundle;
  }

  public Path writeNew(Path file) throws IOException {
    return SecureFiles.writeNew(file, (text + "\n").getBytes(StandardCharsets.UTF_8));
  }

  public String producer() {
    return json.get("producer").getAsString();
  }

  public int iin() {
    return json.get("iin").getAsInt();
  }

  public int batch() {
    return json.get("batch").getAsInt();
  }

  public String samId() {
    return json.get("samId").getAsString();
  }

  public long quota() {
    return json.get("quota").getAsLong();
  }

  public long initialTs() {
    return json.get("initialTs").getAsLong();
  }

  public byte[] paramsDigest() {
    return HexUtil.parse(json.get("paramsDigest").getAsString());
  }

  public int f9ValidityDays() {
    return json.get("f9ValidityDays").getAsInt();
  }

  public byte[] samCertificate() {
    return Base64.getDecoder().decode(json.get("samCertificate").getAsString());
  }

  public byte[] rootCertificate() {
    return Base64.getDecoder().decode(json.get("rootCertificate").getAsString());
  }

  public String allocateLine() {
    return json.getAsJsonObject("registry").get("allocate").getAsString();
  }

  public String bindLine() {
    return json.getAsJsonObject("registry").get("bind").getAsString();
  }

  public SamLedgerEntry.Signed genesis() {
    JsonObject genesis = json.getAsJsonObject("genesis");
    return new SamLedgerEntry.Signed(
        SamLedgerEntry.parse(HexUtil.parse(genesis.get("entry").getAsString())),
        HexUtil.parse(genesis.get("sig").getAsString()));
  }

  public String station() {
    return json.getAsJsonObject("handoff").get("station").getAsString();
  }

  public byte[] stationSki() {
    return HexUtil.parse(json.getAsJsonObject("handoff").get("stationSki").getAsString());
  }

  public int scpKeyVersion() {
    return json.getAsJsonObject("handoff").get("scpKeyVersion").getAsInt();
  }

  public byte[] ephemeralPublicKey() {
    return HexUtil.parse(json.getAsJsonObject("handoff").get("ephemeralPublicKey").getAsString());
  }

  public byte[] wrapped() {
    return HexUtil.parse(json.getAsJsonObject("handoff").get("wrapped").getAsString());
  }

  /** Whether the bundle's root signature verifies under {@code root}. */
  public boolean verifies(PublicKey root) {
    try {
      CanonicalJson.verify(text, root);
      return true;
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static byte[] encoded(X509Certificate certificate) {
    try {
      return certificate.getEncoded();
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new IllegalArgumentException("root certificate cannot be encoded", e);
    }
  }
}
