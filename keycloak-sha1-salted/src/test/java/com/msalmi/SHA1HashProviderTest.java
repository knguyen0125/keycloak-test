package com.msalmi;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SHA1HashProviderTest {

    @Test
    public void encodeHelloWorld() {
        final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
        var expected = "3645c6abf66c341bcf60b8e3a58a0834f7dbf673";
        String salt = "5845a1fe";
        var encoded = provider.getEncodedCredentials("password123", 1, salt.getBytes());
        assertTrue(encoded.equals(expected));
    }
}
