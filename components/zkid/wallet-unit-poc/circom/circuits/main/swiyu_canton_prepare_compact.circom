pragma circom 2.2.3;

include "../swiyu-canton-prepare-base.circom";

component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuCantonPrepareBase(896, 256, 600);
