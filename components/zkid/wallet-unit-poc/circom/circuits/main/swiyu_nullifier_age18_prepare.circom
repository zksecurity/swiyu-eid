pragma circom 2.2.3;

include "../swiyu-nullifier-age18-prepare.circom";

component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuNullifierAge18Prepare();
