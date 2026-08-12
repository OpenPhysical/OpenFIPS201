package dev.mistial.tools.openfips201.common;

/**
 * Determines whether a PIV SELECT response advertises credential-backed secure messaging.
 *
 * <p>A build may contain CS2 or CS7 code without advertising either suite. NIST SP 800-73-5 Part 2,
 * Section 3.1.1 says that {@code 0x27} or {@code 0x2E} in the Application Property Template means
 * both that the suite is supported and that the PIV Card Application possesses an appropriately
 * sized PIV Secure Messaging key. Table 5 requires each identifier to be encoded as a one-byte
 * {@code 0x80} value inside the {@code 0xAC} Cryptographic Algorithm Identifier Template. Bytes
 * elsewhere in the SELECT response are therefore irrelevant.
 */
public final class SecureMessagingAdvertisement {
  private static final int TAG_APPLICATION_PROPERTY_TEMPLATE = 0x61;
  private static final int TAG_CRYPTOGRAPHIC_ALGORITHMS = 0xAC;
  private static final int TAG_ALGORITHM_IDENTIFIER = 0x80;

  private static final int ALGORITHM_CS2 = 0x27;
  private static final int ALGORITHM_CS7 = 0x2E;

  private SecureMessagingAdvertisement() {}

  public static boolean isPresent(byte[] apt) {
    // Parse the TLV hierarchy instead of searching for 80 01 27/2E byte patterns. Section 3.1.1
    // assigns discovery semantics only to algorithm identifiers nested in the 0xAC template.
    BerTlvReader.Tlv application = read(apt, 0, apt == null ? 0 : apt.length);
    if (application == null || application.tag != TAG_APPLICATION_PROPERTY_TEMPLATE) {
      return false;
    }

    BerTlvReader.Tlv algorithms = findDirectChild(apt, application, TAG_CRYPTOGRAPHIC_ALGORITHMS);
    return algorithms != null && containsSecureMessagingSuite(apt, algorithms);
  }

  private static boolean containsSecureMessagingSuite(byte[] encoded, BerTlvReader.Tlv algorithms) {
    int offset = algorithms.valueOffset;
    while (offset < algorithms.nextOffset) {
      BerTlvReader.Tlv identifier = read(encoded, offset, algorithms.nextOffset);
      if (identifier == null) {
        return false;
      }
      if (identifier.tag == TAG_ALGORITHM_IDENTIFIER && identifier.length == 1) {
        int algorithm = encoded[identifier.valueOffset] & 0xFF;
        if (algorithm == ALGORITHM_CS2 || algorithm == ALGORITHM_CS7) {
          return true;
        }
      }
      offset = identifier.nextOffset;
    }
    return false;
  }

  private static BerTlvReader.Tlv findDirectChild(
      byte[] encoded, BerTlvReader.Tlv parent, int requestedTag) {
    int offset = parent.valueOffset;
    while (offset < parent.nextOffset) {
      BerTlvReader.Tlv child = read(encoded, offset, parent.nextOffset);
      if (child == null) {
        return null;
      }
      if (child.tag == requestedTag) {
        return child;
      }
      offset = child.nextOffset;
    }
    return null;
  }

  private static BerTlvReader.Tlv read(byte[] encoded, int offset, int limit) {
    if (encoded == null || offset < 0 || offset >= limit) {
      return null;
    }
    try {
      return BerTlvReader.read(encoded, offset, limit);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }
}
