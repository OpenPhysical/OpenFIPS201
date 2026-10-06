/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.issuance;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.crypto.EcdhKeyTransport;
import dev.mistial.tools.openfips201.crypto.KeyIdentifiers;
import dev.mistial.tools.openfips201.crypto.SigningKey;
import dev.mistial.tools.openfips201.gp.CardKeyDerivationService;
import dev.mistial.tools.openfips201.gp.DerivedScpKeys;
import dev.mistial.tools.openfips201.opid.OpidCipher;
import dev.mistial.tools.openfips201.producer.StationGuard;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Software stand-ins for the producer HSM: a root CA and a card master key. */
public final class IssuanceTestKeys {
  private static final long DAY = 86_400_000L;

  private IssuanceTestKeys() {}

  public static KeyPair p256() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** A root CA in the producer root profile (self-signed, cA, keyCertSign|cRLSign, SKI). */
  public static final class TestRoot implements SigningKey {
    public final KeyPair keyPair = p256();
    private final X509Certificate certificate;

    public TestRoot() {
      try {
        X500Name name = new X500Name("CN=Issuance Test Root,O=OpenPhysical Test");
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder =
            new X509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now),
                new Date(now - DAY),
                new Date(now + 20 * 365 * DAY),
                name,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(
            Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            new DEROctetString(KeyIdentifiers.ski(keyPair.getPublic())));
        byte[] der =
            builder
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()))
                .getEncoded();
        certificate =
            (X509Certificate)
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public PublicKey publicKey() {
      return keyPair.getPublic();
    }

    @Override
    public byte[] sign(String jcaAlgorithm, byte[] message) throws Exception {
      Signature signature = Signature.getInstance(jcaAlgorithm);
      signature.initSign(keyPair.getPrivate());
      signature.update(message);
      return signature.sign();
    }

    @Override
    public String description() {
      return "test-root";
    }

    @Override
    public X509Certificate certificate() {
      return certificate;
    }
  }

  /** SCP keys derived locally from a fixed master and the card's KDD. */
  public static ScpKeyDeriver localDeriver() {
    return new ScpKeyDeriver() {
      @Override
      public DerivedScpKeys derive(byte[] kdd) throws Exception {
        return new CardKeyDerivationService()
            .derive(HexUtil.parse("00112233445566778899AABBCCDDEEFF"), HexUtil.format(kdd), 2);
      }

      @Override
      public String description() {
        return "local-test-master";
      }
    };
  }

  /** A fresh P-256 scalar in [1, n-1]. */
  static BigInteger scalar() {
    return ((ECPrivateKey) p256().getPrivate()).getS();
  }

  /**
   * Software root-station custody: {@link TestRoot}, one FF1 key per IIN, the RFC 3394 ECDH key
   * transport of {@code Pkcs11KeyTransport} and an in-memory registry head.
   */
  public static final class LocalRoot implements RootKeys {
    public final TestRoot root = new TestRoot();
    private final Map<Integer, byte[]> iinKeys = new HashMap<Integer, byte[]>();
    private byte[] registryHead;
    public boolean development;

    @Override
    public SigningKey rootSigner() {
      return root;
    }

    @Override
    public X509Certificate rootCertificate() {
      return root.certificate();
    }

    private byte[] iinKey(int iin) {
      byte[] key = iinKeys.get(iin);
      if (key == null) {
        key = OpidCipher.generateKey(new SecureRandom());
        iinKeys.put(iin, key);
      }
      return key;
    }

    @Override
    public String ensureIinKey(int iin) {
      iinKey(iin);
      return String.format("local-iin-%04d-fpe", iin);
    }

    @Override
    public OpidCipher iinCipher(int iin) {
      return OpidCipher.of(iinKey(iin).clone());
    }

    @Override
    public WrappedKey wrapIinKeyForSam(int iin, byte[] samTransportPub) {
      BigInteger ephemeral = scalar();
      byte[] ephemeralPub = EcdhKeyTransport.publicPoint(ephemeral);
      byte[] sharedInfo =
          EcdhKeyTransport.samTransportSharedInfo(samTransportPub, ephemeralPub, iin);
      return new WrappedKey(
          ephemeralPub,
          EcdhKeyTransport.wrapWith(ephemeral, samTransportPub, iinKey(iin), sharedInfo));
    }

    @Override
    public WrappedKey wrapSecret(byte[] secret, byte[] recipientPub, byte[] sharedInfo) {
      BigInteger ephemeral = scalar();
      return new WrappedKey(
          EcdhKeyTransport.publicPoint(ephemeral),
          EcdhKeyTransport.wrapWith(ephemeral, recipientPub, secret, sharedInfo));
    }

    @Override
    public byte[] readRegistryHead() {
      return registryHead == null ? null : registryHead.clone();
    }

    @Override
    public void writeRegistryHead(byte[] head) {
      registryHead = head.clone();
    }

    @Override
    public boolean isDevelopment() {
      return development;
    }
  }

  /**
   * Software production-station custody: the public root certificate, a station handoff ECDH key
   * and {@link #localDeriver()}.
   */
  public static final class LocalCustody implements Custody {
    private final X509Certificate root;
    private final BigInteger station = scalar();
    private final ScpKeyDeriver deriver = localDeriver();
    public boolean development;

    public LocalCustody(X509Certificate root) {
      this.root = root;
    }

    @Override
    public X509Certificate rootCertificate() {
      return root;
    }

    @Override
    public ScpKeyDeriver keyDeriver() {
      return deriver;
    }

    @Override
    public byte[] stationPoint() {
      return EcdhKeyTransport.publicPoint(station);
    }

    @Override
    public byte[] unwrapHandoff(byte[] ephemeralPub, byte[] wrapped, byte[] sharedInfo) {
      return EcdhKeyTransport.unwrapFrom(station, ephemeralPub, wrapped, sharedInfo);
    }

    @Override
    public void requireProductionClean(String producer) throws IOException {
      StationGuard.requireNoLcgRecords(producer);
    }

    @Override
    public String custody() {
      return development ? "softhsm-dev" : "test";
    }

    @Override
    public boolean isDevelopment() {
      return development;
    }
  }
}
