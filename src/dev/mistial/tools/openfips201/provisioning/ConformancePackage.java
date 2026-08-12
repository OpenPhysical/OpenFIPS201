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

package dev.mistial.tools.openfips201.provisioning;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Transport-agnostic description of a card personalisation package.
 *
 * <p>Produced by loaders such as {@link IcamCardFolder} and consumed by {@link
 * ConformanceProvisioner}. Holds raw object payloads (already in the form written under the PUT
 * DATA {@code 0x53} value, or discovery-form for tag {@code 7E}) plus importable key material.
 */
public final class ConformancePackage {
  /** How the PUT DATA command addresses this object. */
  public enum PutForm {
    /** Standard tag-list form: {@code 5C <id> 53 <body>}. */
    TAG_LIST,
    /** Discovery form: payload already begins with {@code 7E}. */
    DISCOVERY
  }

  public final String credentialId;
  public final Path sourceDirectory;
  public final byte[] pin;
  public final byte[] puk;
  /** Optional PIV card-application management key. Absence means administration requires SCP. */
  public final ManagementKeyMaterial managementKey;

  public final List<DataObject> dataObjects;
  public final List<KeyMaterial> keys;

  public ConformancePackage(
      String credentialId,
      Path sourceDirectory,
      byte[] pin,
      byte[] puk,
      ManagementKeyMaterial managementKey,
      List<DataObject> dataObjects,
      List<KeyMaterial> keys) {
    this.credentialId = credentialId;
    this.sourceDirectory = sourceDirectory;
    this.pin = AdminTlv.copyOf(pin);
    this.puk = AdminTlv.copyOf(puk);
    this.managementKey = managementKey;
    this.dataObjects = Collections.unmodifiableList(new ArrayList<DataObject>(dataObjects));
    this.keys = Collections.unmodifiableList(new ArrayList<KeyMaterial>(keys));
  }

  /** Explicit 9B mechanism and key bytes. This must never be inferred from loader defaults. */
  public static final class ManagementKeyMaterial {
    public final byte algorithm;
    public final byte[] key;

    public ManagementKeyMaterial(byte algorithm, byte[] key) {
      if (key == null || key.length == 0) {
        throw new IllegalArgumentException("management key bytes are required");
      }
      this.algorithm = algorithm;
      this.key = AdminTlv.copyOf(key);
    }
  }

  /** A PIV data object ready to create and write. */
  public static final class DataObject {
    public final byte[] id;
    public final String label;
    public final byte modeContact;
    public final byte modeContactless;
    public final PutForm putForm;
    /** Body for tag-list form (value of {@code 53}), or full discovery payload for {@code 7E}. */
    public final byte[] payload;

    public DataObject(
        byte[] id,
        String label,
        byte modeContact,
        byte modeContactless,
        PutForm putForm,
        byte[] payload) {
      this.id = AdminTlv.copyOf(id);
      this.label = label;
      this.modeContact = modeContact;
      this.modeContactless = modeContactless;
      this.putForm = putForm;
      this.payload = AdminTlv.copyOf(payload);
    }
  }

  /** An asymmetric key to create and import, optionally bound to a certificate object. */
  public static final class KeyMaterial {
    public final byte slot;
    public final String label;
    public final byte algorithm;
    public final byte role;
    public final byte attributes;
    public final byte modeContact;
    public final byte modeContactless;
    public final PrivateKey privateKey;
    public final X509Certificate certificate;

    public KeyMaterial(
        byte slot,
        String label,
        byte algorithm,
        byte role,
        byte attributes,
        byte modeContact,
        byte modeContactless,
        PrivateKey privateKey,
        X509Certificate certificate) {
      this.slot = slot;
      this.label = label;
      this.algorithm = algorithm;
      this.role = role;
      this.attributes = attributes;
      this.modeContact = modeContact;
      this.modeContactless = modeContactless;
      this.privateKey = privateKey;
      this.certificate = certificate;
    }
  }
}
