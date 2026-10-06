package dev.mistial.openphysical.sam;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javacard.framework.JCSystem;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Time;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/** Shared white-box fixture: SAM objects outside the simulator with JCSystem mocked. */
final class WhiteBox {
  private WhiteBox() {}

  /** Enters a jCardEngine context so platform key and crypto objects can be built. */
  static AutoCloseable engineContext() throws Exception {
    pro.javacard.engine.JavaCardEngine engine = pro.javacard.engine.JavaCardEngine.create();
    return (AutoCloseable) engine.getClass().getMethod("asCurrent").invoke(engine);
  }

  static void mockTransientStorage(MockedStatic<JCSystem> system) {
    system
        .when(() -> JCSystem.makeTransientByteArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new byte[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientShortArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new short[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientObjectArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new Object[(short) call.getArgument(0)]);
    system
        .when(() -> JCSystem.makeTransientBooleanArray(Mockito.anyShort(), Mockito.anyByte()))
        .thenAnswer(call -> new boolean[(short) call.getArgument(0)]);
  }

  /** Records transaction events and models the nesting depth. */
  static final class Transactions {
    final List<String> events = new ArrayList<>();
    int depth;

    void install(MockedStatic<JCSystem> system, Runnable onBegin, Runnable onCommit) {
      system
          .when(JCSystem::beginTransaction)
          .thenAnswer(
              call -> {
                depth = 1;
                events.add("begin");
                onBegin.run();
                return null;
              });
      system
          .when(JCSystem::commitTransaction)
          .thenAnswer(
              call -> {
                onCommit.run();
                depth = 0;
                events.add("commit");
                return null;
              });
      system
          .when(JCSystem::abortTransaction)
          .thenAnswer(
              call -> {
                depth = 0;
                events.add("abort");
                return null;
              });
      system.when(JCSystem::getTransactionDepth).thenAnswer(call -> (byte) depth);
      system.when(JCSystem::getMaxCommitCapacity).thenReturn((short) 0x7FFF);
    }
  }

  /** An OPERATIONAL SAM (format 2, k = 5) with a pending nonce and a valid ISSUE request. */
  static final class Fixture {
    final byte[] io = new byte[SamConst.LENGTH_IO_BUFFER];
    final byte[] scratch = new byte[SamConst.LENGTH_SCRATCH];
    final byte[] nonce = new byte[SamConst.LENGTH_NONCE + 1];
    final SamState state;
    final SamCrypto crypto;
    final SamLedger ledger;
    final DERWriter writer;
    final KeyPair f9 = newP256();
    byte[] request;

    Fixture() throws Exception {
      writer = new DERWriter();
      state = new SamState();
      crypto = new SamCrypto(io);
      ledger = new SamLedger(state, crypto, io, scratch, nonce);

      System.arraycopy(new byte[] {1, 2, 3, 4}, 0, state.issuerDigits, 0, 4);
      System.arraycopy(new byte[] {0, 0, 4, 2}, 0, state.batchDigits, 0, 4);
      System.arraycopy(DecimalLcgTest.digits(86421, 8), 0, state.lcgA, 0, 8);
      System.arraycopy(DecimalLcgTest.digits(7, 8), 0, state.lcgC, 0, 8);
      System.arraycopy(DecimalLcgTest.digits(31415926, 8), 0, state.lcgX0, 0, 8);
      System.arraycopy(DecimalLcgTest.digits(31415926, 8), 0, state.lcgX, 0, 8);
      System.arraycopy(U32Test.u32(10), 0, state.quota, 0, 4);
      System.arraycopy(U32Test.u32(1), 0, state.eventSeq, 0, 4);
      byte[] name = new X500Name("CN=White Box SAM").getEncoded("DER");
      System.arraycopy(name, 0, state.samCert, 0, name.length);
      state.samCertLength = (short) name.length;
      state.samSubjectOffset = 0;
      state.samSubjectLength = (short) name.length;
      System.arraycopy("20000101000000".getBytes(), 0, state.samNotBefore, 0, 14);
      System.arraycopy("20991231235959".getBytes(), 0, state.samNotAfter, 0, 14);
      crypto.generateSamKey();
      byte[] w = new byte[65];
      crypto.samPublic.getW(w, (short) 0);
      System.arraycopy(MessageDigest.getInstance("SHA-256").digest(w), 0, state.samSki, 0, 20);
      byte[] rootPoint = point(newP256());
      crypto.rootPublic.setW(rootPoint, (short) 0, (short) 65);
      crypto.fpeKey.setKey(new byte[32], (short) 0);
      state.lifecycle = SamConst.LC_OPERATIONAL;
      newRequest();
    }

    /** Starts a new issuance (fresh nonce) and builds a valid request for it. */
    void newRequest() throws Exception {
      ledger.beginIssuance();
      byte[] n = java.util.Arrays.copyOf(nonce, 32);
      byte[] point = point(f9);
      java.security.Signature signer = java.security.Signature.getInstance("SHA256withECDSA");
      signer.initSign(f9.getPrivate());
      signer.update("OPF9POP".getBytes());
      signer.update(n);
      signer.update(point);
      byte[] pop = signer.sign();
      long now = System.currentTimeMillis();
      byte[] validity =
          new DERSequence(
                  new ASN1Encodable[] {
                    new Time(new Date(now)), new Time(new Date(now + 86_400_000L))
                  })
              .getEncoded("DER");
      request =
          concat(
              tlv(0x86, point),
              tlv(0x9E, pop),
              tlv(0x93, validity),
              tlv(0x94, new byte[32]),
              tlv(0x95, new byte[32]));
    }

    /** Stages the request where IssuerSam assembles it, at the top of the I/O buffer. */
    short issue() {
      System.arraycopy(request, 0, io, SamConst.STAGE_ISSUE, request.length);
      return ledger.issue(writer, io, SamConst.STAGE_ISSUE, (short) request.length);
    }
  }

  static boolean isZero(byte[] data) {
    for (byte value : data) {
      if (value != 0) return false;
    }
    return true;
  }

  static KeyPair newP256() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] point(KeyPair keyPair) {
    ECPublicKey key = (ECPublicKey) keyPair.getPublic();
    byte[] out = new byte[65];
    out[0] = 4;
    fixed(key.getW().getAffineX(), out, 1);
    fixed(key.getW().getAffineY(), out, 33);
    return out;
  }

  private static void fixed(BigInteger value, byte[] out, int offset) {
    byte[] raw = value.toByteArray();
    int length = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - length, out, offset + 32 - length, length);
  }

  static byte[] tlv(int tag, byte[] value) {
    byte[] length =
        value.length < 0x80
            ? new byte[] {(byte) value.length}
            : new byte[] {(byte) 0x81, (byte) value.length};
    return concat(new byte[] {(byte) tag}, length, value);
  }

  static byte[] concat(byte[]... parts) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    for (byte[] part : parts) out.write(part, 0, part.length);
    return out.toByteArray();
  }
}
