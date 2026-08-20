pragma circom 2.2.3;

include "../jwt_tx_builder/header-payload-extractor.circom";

template HeaderPayloadExtractorHarness(maxMessageLength, maxB64HeaderLength, maxB64PayloadLength) {
    signal input message[maxMessageLength];
    signal input messageLength;
    signal input periodIndex;
    signal output headerFirst;
    signal output payloadFirst;

    component extractor = HeaderPayloadExtractor(
        maxMessageLength,
        maxB64HeaderLength,
        maxB64PayloadLength
    );
    extractor.message <== message;
    extractor.messageLength <== messageLength;
    extractor.periodIndex <== periodIndex;
    headerFirst <== extractor.header[0];
    payloadFirst <== extractor.payload[0];
}
