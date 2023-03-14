package com.msalmi;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SHA1HashProvider implements PasswordHashProvider {

    private final String providerId;

    public SHA1HashProvider(String providerId) {
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

        byte[] salt = getSalt();
        String encodedPassword = getEncodedCredentials(rawPassword, iterations, salt);
        return PasswordCredentialModel.createFromValues(this.providerId, salt, iterations, encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        return getEncodedCredentials(rawPassword, credential.getPasswordCredentialData().getHashIterations(), credential.getPasswordSecretData().getSalt()).equals(credential.getPasswordSecretData().getValue());
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        if (iterations == -1) {
            iterations = 1;
        }

        byte[] salt = getSalt();
        return getEncodedCredentials(rawPassword, iterations, salt);
    }

    public String getEncodedCredentials(String rawPassword, int iterations, byte[] salt) {
        String encodedPassword = rawPassword;

        try {
            for (int i = 0; i < iterations; i++) {
                SecretKey key = new SecretKeySpec(salt, "HmacSHA1");
                Mac mac = Mac.getInstance("HmacSHA1", new BouncyCastleProvider());
                mac.init(key);

                mac.update(encodedPassword.getBytes());

                byte[] digest = mac.doFinal();

                encodedPassword = String.format("%040x", new BigInteger(1, digest));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return encodedPassword;
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }
}
