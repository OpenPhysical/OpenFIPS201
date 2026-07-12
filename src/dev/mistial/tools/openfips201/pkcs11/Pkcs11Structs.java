/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.pkcs11;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.List;

final class Pkcs11Structs {
  private Pkcs11Structs() {}

  public static final class Attribute extends Structure {
    public NativeLong type;
    public Pointer pValue;
    public NativeLong ulValueLen;

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList("type", "pValue", "ulValueLen");
    }
  }

  public static final class Mechanism extends Structure {
    public NativeLong mechanism;
    public Pointer pParameter;
    public NativeLong ulParameterLen;

    public Mechanism() {}

    Mechanism(long mechanism) {
      this.mechanism = new NativeLong(mechanism);
      this.pParameter = null;
      this.ulParameterLen = new NativeLong(0);
    }

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList("mechanism", "pParameter", "ulParameterLen");
    }
  }

  public static final class MechanismInfo extends Structure {
    public NativeLong ulMinKeySize;
    public NativeLong ulMaxKeySize;
    public NativeLong flags;

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList("ulMinKeySize", "ulMaxKeySize", "flags");
    }
  }

  public static final class TokenInfo extends Structure {
    public byte[] label = new byte[32];
    public byte[] manufacturerID = new byte[32];
    public byte[] model = new byte[16];
    public byte[] serialNumber = new byte[16];
    public NativeLong flags;
    public NativeLong ulMaxSessionCount;
    public NativeLong ulSessionCount;
    public NativeLong ulMaxRwSessionCount;
    public NativeLong ulRwSessionCount;
    public NativeLong ulMaxPinLen;
    public NativeLong ulMinPinLen;
    public NativeLong ulTotalPublicMemory;
    public NativeLong ulFreePublicMemory;
    public NativeLong ulTotalPrivateMemory;
    public NativeLong ulFreePrivateMemory;
    public Version hardwareVersion = new Version();
    public Version firmwareVersion = new Version();
    public byte[] utcTime = new byte[16];

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList(
          "label",
          "manufacturerID",
          "model",
          "serialNumber",
          "flags",
          "ulMaxSessionCount",
          "ulSessionCount",
          "ulMaxRwSessionCount",
          "ulRwSessionCount",
          "ulMaxPinLen",
          "ulMinPinLen",
          "ulTotalPublicMemory",
          "ulFreePublicMemory",
          "ulTotalPrivateMemory",
          "ulFreePrivateMemory",
          "hardwareVersion",
          "firmwareVersion",
          "utcTime");
    }
  }

  public static final class Version extends Structure {
    public byte major;
    public byte minor;

    @Override
    protected List<String> getFieldOrder() {
      return Arrays.asList("major", "minor");
    }
  }
}
