pragma circom 2.2.3;

include "../swiyu-age18-status.circom";

// Credential-time stage. Online holder signature, age/time checks, status
// authentication, and session commitments are removed. The native Spartan
// wrapper reclassifies all eleven Circom outputs as hidden shared witness rows.
component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuAge18Status(896, 256, 600, 17, 0, 1, 0);
