pragma circom 2.2.3;

include "../swiyu-nullifier-prepare.circom";

component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuNullifierAuthenticatedPrepare();
