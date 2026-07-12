Secure Messaging/VCI vectors from the good cards with VCI support in NIST SP 33 (2,3,4,5,16).

The card with just SM but no VCI was intentionally omitted due to the use of functionality which is contact/vci-only in enrolment.

Vectors intentionally demonstrate a VCI-based enrolment over contactless. The enrolment phase thus requires specifying the pairing code. Once VCI is established, enrolment continues as though it was over contact, except for reading of the pairing code object. This is also the reason for exhaustively enumeration and capture of PIV data objects. The additional number of APDUs provides increased surface for SM testing.

To simulate separate enrolment vs acceptance times, the card was removed from the field and returned prior to subsequent steps.

My middleware checks the PIN retries remaining prior to authenticating. This is part of anti-lockout policy and is not a requirement of the specification.

Auth against CAK is not VCI protected. The card doesn't require it, and it doesn't add any security. For vector purposes, both the CAK (no PIN/VCI required) and the User Authentication Key (PIN/VCI required) are validated. In practice, one or the other would be validated, not both.
