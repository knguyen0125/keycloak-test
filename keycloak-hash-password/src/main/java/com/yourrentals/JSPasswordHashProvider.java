package com.yourrentals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JSPasswordHashProvider implements PasswordHashProvider {

    private final String providerId;

    public JSPasswordHashProvider(String providerId) {
        this.providerId = providerId;
    }

    @Override
    public void close() {
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return this.providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        if (iterations == -1) {
            iterations = 1;
        }

        byte[] salt = generateSalt();

        String encodedPassword = generateHash("sha1", salt, iterations, rawPassword);
        return PasswordCredentialModel.createFromValues(this.providerId, salt, iterations, encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        // Raw password should be a $-delimited array: [algorithm]$[salt]$[iterations]$[hash]
        // Get the 4
        String[] decoded = credential.getPasswordSecretData().getValue().split("\\$");

        if (decoded.length != 4) {
            return false;
        }

        return generateHash(decoded[0], decoded[1].getBytes(), Integer.parseInt(decoded[2]), rawPassword).equals(credential.getPasswordSecretData().getValue());
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        if (iterations == -1) {
            iterations = 1;
        }

        byte[] salt = generateSalt();

        return generateHash("sha1", salt, iterations, rawPassword);
    }

    /**
     * Convert JS Crypto algorithm to Java Crypto algorithm
     */
    public String getJavaAlgorithm(String jsAlgorithm) {
        return "Hmac" + jsAlgorithm.toUpperCase();
    }

    public String generateHash(String algorithm, byte[] salt, int iterations, String rawPassword) {
        if (iterations == -1) {
            iterations = 1;
        }

        try {
            String hash = rawPassword;
            for (int i = 0; i < iterations; i++) {
                // const hmac = crypto.createHmac(algorithm, salt)
                Mac mac = Mac.getInstance(getJavaAlgorithm(algorithm));

                SecretKey key = new SecretKeySpec(salt, algorithm);
                mac.init(key);

                // hmac.update(hash)
                mac.update(hash.getBytes());

                // hash = hmac.digest('hex')
                hash = String.format("%040x", new BigInteger(1, mac.doFinal()));
            }

            return algorithm + "$" + new String(salt, StandardCharsets.UTF_8) + "$" + iterations + "$" + hash;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] generateSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }
}
