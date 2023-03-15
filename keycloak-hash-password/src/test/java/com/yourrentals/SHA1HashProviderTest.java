package com.yourrentals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SHA1HashProviderTest {

    @Test
    public void encodeHelloWorld() {
        final var provider = new JSPasswordHashProvider(JSPasswordHashProviderFactory.ID);
        String algorithm = "sha1";
        int iterations = 1;
        String salt = "5845a1fe";
        String password = "password123";

        String expected = "3645c6abf66c341bcf60b8e3a58a0834f7dbf673";
        String expectedHash = String.format("%s$%s$%s$%s", algorithm, salt, iterations, expected);


        var encoded = provider.generateHash(algorithm, salt.getBytes(), iterations, password);

        assertEquals(encoded, expectedHash);
    }
}
