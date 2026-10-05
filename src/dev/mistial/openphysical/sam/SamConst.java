/******************************************************************************
 * MIT License
 *
 * Project: OpenPhysical Issuer SAM
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

package dev.mistial.openphysical.sam;

/**
 * Constants for the issuer SAM: lifecycle values, instructions, status words, wire-contract
 * prefixes and OIDs, and the documented offsets of every scratch region.
 */
final class SamConst {
  private SamConst() {}

  // Version 0.1, reported in the SELECT FCI (tag 80) and STATUS (tag 8E).
  static final byte VERSION_MAJOR = (byte) 0x00;
  static final byte VERSION_MINOR = (byte) 0x01;

  //
  // Lifecycle. The values have pairwise Hamming distance of at least four so a single fault cannot
  // turn one valid state into another; they are only ever compared with ==.
  //
  static final byte LC_INSTALLED = (byte) 0x5A;
  static final byte LC_PARAMS_SET = (byte) 0x69;
  static final byte LC_KEY_GENERATED = (byte) 0x96;
  static final byte LC_CERT_LOADED = (byte) 0xA5;
  static final byte LC_OPERATIONAL = (byte) 0xC3;
  static final byte LC_TERMINATED = (byte) 0x3C;
  /** Issuance closed: no further BEGIN, ISSUE or TOP UP; reporting, VOID and DECIPHER remain. */
  static final byte LC_CLOSED = (byte) 0xE1;

  //
  // Classes and instructions.
  //
  static final byte CLA_ISO = (byte) 0x00;
  static final byte CLA_PROPRIETARY = (byte) 0x80;
  static final byte CLA_PROPRIETARY_SM = (byte) 0x84;
  static final byte CLA_CHAIN_BIT = (byte) 0x10;

  static final byte INS_SELECT = (byte) 0xA4;
  static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
  static final byte INS_GP_EXTERNAL_AUTHENTICATE = (byte) 0x82;
  static final byte INS_GET_RESPONSE = (byte) 0xC0;
  static final byte INS_PUT_PARAMETERS = (byte) 0xD0;
  static final byte INS_SET_OPERATOR_PIN = (byte) 0xD2;
  static final byte INS_GENERATE_SAM_KEY = (byte) 0x46;
  static final byte INS_LOAD_SAM_CERTIFICATE = (byte) 0xD4;
  static final byte INS_LOCK = (byte) 0xD6;
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_BEGIN_ISSUANCE = (byte) 0x84;
  static final byte INS_ISSUE = (byte) 0x2A;
  static final byte INS_TOP_UP = (byte) 0x32;
  static final byte INS_GET_DATA = (byte) 0xCA;
  static final byte INS_TERMINATE = (byte) 0xE6;
  static final byte INS_DECIPHER = (byte) 0x2C;
  static final byte INS_GENERATE_TRANSPORT_KEY = (byte) 0x4A;
  static final byte INS_CHANGE_OPERATOR_PIN = (byte) 0x24;
  static final byte INS_VOID = (byte) 0x2E;
  static final byte INS_CLOSE = (byte) 0xE8;
  static final short SW_FOREIGN_IIN = (short) 0x6A88;

  static final byte P2_OPERATOR_PIN = (byte) 0x81;
  static final byte P2_ISSUE_F9 = (byte) 0xF9;

  static final byte GET_DATA_STATUS = (byte) 0x01;
  static final byte GET_DATA_SAM_CERTIFICATE = (byte) 0x02;
  static final byte GET_DATA_LAST_ENTRY = (byte) 0x03;
  static final byte GET_DATA_PARAMETERS = (byte) 0x04;
  static final byte GET_DATA_LAST_RESULT = (byte) 0x05;
  static final byte GET_DATA_SIGNED = (byte) 0x01;

  //
  // Status words that ISO7816 does not name.
  //
  /** Signature verification failed; persistent state is unchanged. */
  static final short SW_VERIFICATION_FAILED = (short) 0x6300;
  /** Failure after the issuance commit; the OPID is burned and GET LAST ENTRY recovers it. */
  static final short SW_FAILURE_AFTER_COMMIT = (short) 0x6500;
  /** Quota or OPID period exhausted, or insufficient commit capacity. */
  static final short SW_EXHAUSTED = (short) 0x6A84;
  /** Personalization command after LOCK. */
  static final short SW_LOCKED = (short) 0x6986;
  /** Unexpected error before any commit. */
  static final short SW_UNEXPECTED = (short) 0x6F00;

  //
  // Sizes.
  //
  static final short LENGTH_IO_BUFFER = (short) 1024;
  static final short LENGTH_SCRATCH = (short) 320;
  static final short LENGTH_NONCE = (short) 32;
  static final short OFFSET_NONCE_STATE = LENGTH_NONCE;
  static final byte NONCE_ACTIVE = (byte) 0xA5;
  static final short LENGTH_HASH = (short) 32;
  static final short LENGTH_KCV = (short) 16;
  static final short LENGTH_FPE_KEY = (short) 32;
  static final short LENGTH_SKI = (short) 20;
  static final short LENGTH_POINT = (short) 65;
  static final short LENGTH_SPKI = (short) 91;
  static final short LENGTH_SIGNATURE_MIN = (short) 8;
  static final short LENGTH_SIGNATURE_MAX = (short) 72;
  static final short LENGTH_TIME = (short) 14;
  static final short LENGTH_TIMESTAMP = (short) 8;
  static final short LENGTH_U32 = (short) 4;
  static final short LENGTH_DIGITS = (short) 8;
  static final short LENGTH_OPID = (short) 17;
  static final short LENGTH_LAST_ENTRY = (short) 160;
  static final short LENGTH_F9_TEMPLATE_MAX = (short) 96;
  static final short LENGTH_SAM_SUBJECT_MAX = (short) 128;
  static final short LENGTH_SAM_CERT_MAX = (short) 1024;
  static final short LENGTH_PIN_MIN = (short) 6;
  static final short LENGTH_PIN_MAX = (short) 16;
  static final byte PIN_TRIES = (byte) 5;
  /** LOCK requires at least this much commit capacity for the per-event transactions. */
  static final short MIN_COMMIT_CAPACITY = (short) 512;

  static final short LENGTH_VALIDITY_MAX = (short) 64;
  static final short LENGTH_STATUS_NONCE_MIN = (short) 16;
  static final short LENGTH_STATUS_NONCE_MAX = (short) 32;

  //
  // Incoming command staging inside the I/O buffer. PUT PARAMETERS is staged in the upper half so
  // the ECPointValidator workspace (I/O buffer offsets 0..335) does not overlap the packet.
  //
  static final short STAGE_PARAMETERS = (short) 512;
  static final short STAGE_PARAMETERS_MAX = (short) 512;
  static final short STAGE_CERTIFICATE = (short) 0;
  static final short STAGE_CERTIFICATE_MAX = LENGTH_SAM_CERT_MAX;
  /** I/O buffer offset for public-key comparisons after point validation in ISSUE. */
  static final short IO_POINT_COMPARE = (short) 512;

  //
  // Scratch layout for ISSUE. Regions marked with the same offset are live in disjoint steps, as
  // numbered in the ISSUE order: POP message (steps 2-10, F9 point at +39), ENTRY (steps 11-12),
  // TIMES (step 5), OPID/SEQ/EVENT (steps 8-12), SIGNATURE (steps 13-16).
  //
  static final short S_POP = (short) 0;
  static final short S_POP_NONCE = (short) 7;
  static final short S_POP_POINT = (short) 39;
  static final short LENGTH_POP = (short) 104;
  static final short S_ENTRY = (short) 0;
  static final short S_TIMES = (short) 104;
  static final short S_HASH_TBS = (short) 160;
  static final short S_HASH_AUX = (short) 192;
  static final short S_SIGNATURE = (short) 224;
  static final short S_OPID = (short) 224;
  static final short S_NEXT_SEQ = (short) 242;
  static final short S_NEXT_EVENT = (short) 246;
  static final short S_SERIAL = (short) 296;
  static final short LENGTH_SERIAL = (short) 16;
  static final short S_NEXT_X = (short) 312;
  // FF1 encipherment (step 8), inside the TIMES/HASH regions that are dead between steps 6 and
  // 10: FF1 work area, the 12-digit numeral batch | x and the 4-octet tweak ASCII(IIN).
  static final short S_FF1_WORK = (short) 104;
  static final short S_FF1_DIGITS = (short) 186;
  static final short S_FF1_TWEAK = (short) 198;
  static final short S_FF1_END = (short) 202;

  //
  // Scratch layout for DECIPHER: the FF1 regions above, then the recovered LCG value X, the
  // 16-octet orbit work area (y and the next value), the recovered index digits (little-endian)
  // and the index as u32. The 17 parsed OPID digits are staged at S_FF1_DIGITS - 4.
  //
  static final short S_DEC_X = (short) 0;
  static final short S_DEC_Y = (short) 8;
  static final short S_DEC_N = (short) 24;
  static final short S_DEC_COUNT = (short) 32;

  //
  // Scratch layout for VOID: the issuance number's digits (little-endian), x_seq, the orbit work
  // area, then the FF1 regions above; the entry is staged at S_ENTRY after the OPID is rendered
  // at S_OPID.
  //
  static final short S_VOID_SEQ_DIGITS = (short) 0;
  static final short S_VOID_WORK = (short) 8;
  static final short S_VOID_X = (short) 16;
  static final short S_VOID_NEXT = (short) 24;
  static final short S_VOID_U32 = (short) 32;
  static final short S_VOID_ENTRY = (short) 0;

  //
  // Scratch layout for the PUT PARAMETERS v5 key unwrap (validation phase, before any write):
  // ECDH secret Z, the transport public point, the KEK, and the RFC 3394 register A | R1..R4.
  // The unwrapped key is R1..R4 at S_KW_KEY.
  //
  static final short S_KW_Z = (short) 96;
  static final short S_KW_POINT = (short) 128;
  static final short S_KW_KEK = (short) 200;
  static final short S_KW_REGISTER = (short) 232;
  static final short S_KW_KEY = (short) 240;
  static final short S_KW_BLOCK = (short) 272;
  static final short LENGTH_WRAPPED_KEY = (short) 40;

  //
  // Scratch layout for TOP UP: the signed message (step 1) and then the entry share offset 0.
  //
  static final short S_TOPUP_MESSAGE = (short) 0;
  static final short S_NEW_QUOTA = (short) 160;
  static final short S_TOPUP_EVENT = (short) 164;

  //
  // Scratch layout for PUT PARAMETERS: u32 values, a division work area and digit staging.
  //
  static final short S_PRM_ISSUER = (short) 4;
  static final short S_PRM_BATCH = (short) 8;
  static final short S_PRM_QUOTA = (short) 12;
  static final short S_PRM_SEED = (short) 16;
  static final short S_PRM_MODULUS = (short) 20;
  static final short S_PRM_MULTIPLIER = (short) 24;
  static final short S_PRM_INCREMENT = (short) 28;
  static final short S_PRM_WORK = (short) 32;
  static final short S_PRM_ISSUER_DIGITS = (short) 64;
  static final short S_PRM_BATCH_DIGITS = (short) 68;
  static final short S_PRM_X0_DIGITS = (short) 72;
  static final short S_PRM_A_DIGITS = (short) 80;
  static final short S_PRM_C_DIGITS = (short) 88;
  static final short S_PRM_KCV = (short) 96; // 60-octet KCV work area, then the 16-octet KCV
  static final short S_PARAMS_DIGEST = (short) 176;
  static final short S_PARAMS_MESSAGE = (short) 224; // 69-octet paramsDigest v3 preimage
  // Jump-map composition (before the KCV): running pair (A, C), next pair and a zero increment.
  static final short S_JUMP_A = (short) 96;
  static final short S_JUMP_C = (short) 104;
  static final short S_JUMP_NEXT_A = (short) 112;
  static final short S_JUMP_NEXT_C = (short) 120;
  static final short S_JUMP_ZERO = (short) 128;

  //
  // Scratch layout for LOAD SAM CERTIFICATE and LOCK.
  //
  static final short S_CERT_SPKI = (short) 0;
  static final short S_CERT_TIMES = (short) 128;
  static final short S_CERT_U32 = (short) 156;
  static final short S_CERT_WORK = (short) 160;
  static final short S_CERT_DIGITS = (short) 164;
  static final short S_CERT_ALLOCATION = (short) 208; // allocationSeq (u32)
  static final short S_CERT_REGISTRY = (short) 212; // registryHead (32)
  static final short S_LOCK_HEAD = (short) 160;

  //
  // Wire-contract prefixes (shared with the host and the PIV applet).
  //
  // "OPSAMLE1": ledger entry domain prefix; its first octet is never 0x30.
  static final byte[] PREFIX_ENTRY = {
    (byte) 'O', (byte) 'P', (byte) 'S', (byte) 'A', (byte) 'M', (byte) 'L', (byte) 'E', (byte) '1'
  };
  // "OPF9POP": proof of possession of the card F9 key over the SAM nonce.
  static final byte[] PREFIX_POP = {
    (byte) 'O', (byte) 'P', (byte) 'F', (byte) '9', (byte) 'P', (byte) 'O', (byte) 'P'
  };
  // "OPSAMTOPUP1": root-signed quota top-up.
  static final byte[] PREFIX_TOPUP = {
    (byte) 'O',
    (byte) 'P',
    (byte) 'S',
    (byte) 'A',
    (byte) 'M',
    (byte) 'T',
    (byte) 'O',
    (byte) 'P',
    (byte) 'U',
    (byte) 'P',
    (byte) '1'
  };
  // "OPSAMSTAT1": SAM-signed STATUS over a host nonce.
  static final byte[] PREFIX_STATUS = {
    (byte) 'O',
    (byte) 'P',
    (byte) 'S',
    (byte) 'A',
    (byte) 'M',
    (byte) 'S',
    (byte) 'T',
    (byte) 'A',
    (byte) 'T',
    (byte) '1'
  };
  // "OPSAMPRM3": paramsDigest v3 domain prefix (shared wire contract with host
  // OpidSequence.paramsDigest).
  static final byte[] PREFIX_PARAMS = {
    (byte) 'O',
    (byte) 'P',
    (byte) 'S',
    (byte) 'A',
    (byte) 'M',
    (byte) 'P',
    (byte) 'R',
    (byte) 'M',
    (byte) '3'
  };
  // "OPSAMFPEKCV1": FF1 key check value domain prefix (shared wire contract with host
  // OpidCipher.kcv).
  // "OPSAMKT1": SharedInfo prefix of the transport-key KDF (shared wire contract with the host).
  static final byte[] PREFIX_TRANSPORT = {
    (byte) 'O', (byte) 'P', (byte) 'S', (byte) 'A', (byte) 'M', (byte) 'K', (byte) 'T', (byte) '1'
  };
  // X9.63 KDF counter for the single 32-octet output block.
  static final byte[] KDF_COUNTER_1 = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
  // RFC 3394 Section 2.2.3.1 default initial value.
  static final byte[] KW_IV = {
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6,
    (byte) 0xA6
  };

  static final byte[] PREFIX_KCV = {
    (byte) 'O',
    (byte) 'P',
    (byte) 'S',
    (byte) 'A',
    (byte) 'M',
    (byte) 'F',
    (byte) 'P',
    (byte) 'E',
    (byte) 'K',
    (byte) 'C',
    (byte) 'V',
    (byte) '1'
  };

  static final byte ENTRY_GENESIS = (byte) 0x01;
  static final byte ENTRY_ISSUE = (byte) 0x02;
  static final byte ENTRY_TOPUP = (byte) 0x03;
  static final byte ENTRY_TERMINATE = (byte) 0x04;
  static final byte ENTRY_VOID = (byte) 0x05;
  static final byte ENTRY_CLOSE = (byte) 0x06;
  /** CLOSE entry: header | issued(4) | quota(4). */
  static final short LENGTH_CLOSE_ENTRY = (short) 73;
  /** "OPSAMLE1"(8) | type(1) | samSki(20) | eventSeq(4) | prevHead(32). */
  static final short LENGTH_ENTRY_HEADER = (short) 65;

  static final short ENTRY_OFFSET_TYPE = (short) 8;
  static final short ENTRY_OFFSET_SKI = (short) 9;
  static final short ENTRY_OFFSET_EVENT = (short) 29;
  static final short ENTRY_OFFSET_PREV_HEAD = (short) 33;

  //
  // OIDs (content octets only).
  //
  // 1.3.6.1.4.1.57923.20.10.10.1: SAM parameters packet (version 4).
  static final byte[] OID_PARAMETERS = {
    (byte) 0x2B,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x04,
    (byte) 0x01,
    (byte) 0x83,
    (byte) 0xC4,
    (byte) 0x43,
    (byte) 0x14,
    (byte) 0x0A,
    (byte) 0x0A,
    (byte) 0x01
  };
  // 1.3.6.1.4.1.57923.20.10.10.2: F9 issuance extension.
  static final byte[] OID_ISSUANCE_EXTENSION = {
    (byte) 0x2B,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x04,
    (byte) 0x01,
    (byte) 0x83,
    (byte) 0xC4,
    (byte) 0x43,
    (byte) 0x14,
    (byte) 0x0A,
    (byte) 0x0A,
    (byte) 0x02
  };
  // 1.3.6.1.4.1.57923.20.10.10.3: root-signed SAM batch extension.
  static final byte[] OID_BATCH_EXTENSION = {
    (byte) 0x2B,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x04,
    (byte) 0x01,
    (byte) 0x83,
    (byte) 0xC4,
    (byte) 0x43,
    (byte) 0x14,
    (byte) 0x0A,
    (byte) 0x0A,
    (byte) 0x03
  };
  static final byte[] OID_BASIC_CONSTRAINTS = {(byte) 0x55, (byte) 0x1D, (byte) 0x13};
  static final byte[] OID_KEY_USAGE = {(byte) 0x55, (byte) 0x1D, (byte) 0x0F};
  static final byte[] OID_SUBJECT_KEY_IDENTIFIER = {(byte) 0x55, (byte) 0x1D, (byte) 0x0E};
  static final byte[] OID_AUTHORITY_KEY_IDENTIFIER = {(byte) 0x55, (byte) 0x1D, (byte) 0x23};
  static final byte[] OID_SERIAL_NUMBER = {(byte) 0x55, (byte) 0x04, (byte) 0x05};

  // AlgorithmIdentifier ecdsa-with-SHA256 (RFC 5758 Section 3.2: parameters MUST be absent).
  static final byte[] DER_ECDSA_WITH_SHA256 = {
    (byte) 0x30,
    (byte) 0x0A,
    (byte) 0x06,
    (byte) 0x08,
    (byte) 0x2A,
    (byte) 0x86,
    (byte) 0x48,
    (byte) 0xCE,
    (byte) 0x3D,
    (byte) 0x04,
    (byte) 0x03,
    (byte) 0x02
  };
  // [0] EXPLICIT Version v3.
  static final byte[] DER_VERSION_V3 = {
    (byte) 0xA0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02
  };
  // SubjectPublicKeyInfo prefix for id-ecPublicKey / prime256v1 followed by the 65-octet point.
  static final byte[] DER_SPKI_P256_PREFIX = {
    (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2A,
    (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x02, (byte) 0x01, (byte) 0x06,
    (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D, (byte) 0x03,
    (byte) 0x01, (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00
  };
  // F9 BasicConstraints extension: critical, cA TRUE, pathLenConstraint 0.
  static final byte[] DER_F9_BASIC_CONSTRAINTS = {
    (byte) 0x30, (byte) 0x12, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x13,
    (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x04, (byte) 0x08, (byte) 0x30, (byte) 0x06,
    (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x02, (byte) 0x01, (byte) 0x00
  };
  // F9 KeyUsage extension: critical, keyCertSign only.
  static final byte[] DER_F9_KEY_USAGE = {
    (byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x0F,
    (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02,
    (byte) 0x02, (byte) 0x04
  };
  // SubjectKeyIdentifier extension prefix, followed by the 20-octet key identifier.
  static final byte[] DER_SKI_PREFIX = {
    (byte) 0x30,
    (byte) 0x1D,
    (byte) 0x06,
    (byte) 0x03,
    (byte) 0x55,
    (byte) 0x1D,
    (byte) 0x0E,
    (byte) 0x04,
    (byte) 0x16,
    (byte) 0x04,
    (byte) 0x14
  };
  // AuthorityKeyIdentifier extension prefix (keyIdentifier only), followed by the SAM SKI.
  static final byte[] DER_AKI_PREFIX = {
    (byte) 0x30,
    (byte) 0x1F,
    (byte) 0x06,
    (byte) 0x03,
    (byte) 0x55,
    (byte) 0x1D,
    (byte) 0x23,
    (byte) 0x04,
    (byte) 0x18,
    (byte) 0x30,
    (byte) 0x16,
    (byte) 0x80,
    (byte) 0x14
  };
  // SAM certificate BasicConstraints value: cA TRUE, pathLenConstraint exactly 1.
  static final byte[] DER_SAM_BASIC_CONSTRAINTS_VALUE = {
    (byte) 0x30,
    (byte) 0x06,
    (byte) 0x01,
    (byte) 0x01,
    (byte) 0xFF,
    (byte) 0x02,
    (byte) 0x01,
    (byte) 0x01
  };

  //
  // OPID layout v2: IIII (plaintext IIN) | E | L, 17 digits. E = FF1_K(B | X, T) over 12 digits
  // with B the 4-digit batch, X the 8-digit LCG value x_n and T = ASCII(IIII); L is the Luhn digit
  // over the 16 digits IIII | E.
  //
  static final byte ISSUER_DIGITS = (byte) 4;
  static final byte BATCH_DIGITS = (byte) 4;
  static final byte CIN_DIGITS = (byte) 8;
  static final byte ENCIPHERED_DIGITS = (byte) 12;
  /** Jump maps M_j = f^(10^(j-1)), j = 1..8, each an affine pair of 8 little-endian digits. */
  static final short JUMP_MAPS = (short) 8;

  // m = 10^8 as u32 big-endian.
  static final byte[] MODULUS = {(byte) 0x05, (byte) 0xF5, (byte) 0xE1, (byte) 0x00};
}
