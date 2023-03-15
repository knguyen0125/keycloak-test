package com.yourrentals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.models.credential.dto.PasswordSecretData;

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

        String cryptoAlgorithm = "sha1";
        byte[] salt = generateSalt();

        String encodedPassword = generateHash(cryptoAlgorithm, salt, iterations, rawPassword);

        HashMap<String, List<String>> additionalParameters = new HashMap<>();
        additionalParameters.put("cryptoAlgorithm", List.of(cryptoAlgorithm));

        return PasswordCredentialModel.createFromValues(
                new PasswordCredentialData(
                        iterations,
                        this.providerId,
                        additionalParameters
                ),
                new PasswordSecretData(encodedPassword, salt)
        );
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        // Stored password should be a $-delimited string: [algorithm]$[salt]$[iterations]$[hash]
        String[] splitted = credential.getPasswordSecretData().getValue().split("\\$");

        // If the password is not in the expected format, return false
        if (splitted.length != 4) {
            return false;
        }

        String algorithm = splitted[0];
        byte[] salt = splitted[1].getBytes();
        int iterations = Integer.parseInt(splitted[2]);

        return generateHash(algorithm, salt, iterations, rawPassword).equals(credential.getPasswordSecretData().getValue());
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
