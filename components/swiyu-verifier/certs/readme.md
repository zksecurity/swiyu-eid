# Trusted CA certificates

`Dockerfile.dhi` imports each `*.crt` file into the Java and operating-system trust stores.

Only add required roots, verify their SHA-256 fingerprints against the publisher, and rebuild the image.
