pragma circom 2.2.3;

include "../swiyu-residence-prepare-base.circom";

// The frozen fixture uses a 246-character header and 632-character payload.
// Tight 248/632 decoder bounds keep the relation compact; their maximum full
// signing input is 248 + 1 + 632 = 881 <= 887 unpadded bytes in this SHA block.
component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuResidencePrepareBase(896, 248, 632);
