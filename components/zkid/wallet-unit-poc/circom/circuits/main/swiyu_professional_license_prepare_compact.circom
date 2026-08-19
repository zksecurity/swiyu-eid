pragma circom 2.2.3;

include "../swiyu-age18-status.circom";

// Credential-time stage specialized for a professional licence. It retains
// issuer/JOSE/holder/time/status/lookup authentication while statically
// eliminating the unrelated age-disclosure parser. Shared row 2 is zero.
component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuAge18Status(896, 256, 600, 17, 0, 0, 0);
