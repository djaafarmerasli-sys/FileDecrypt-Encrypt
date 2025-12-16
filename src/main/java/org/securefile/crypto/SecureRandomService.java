package org.securefile.crypto;
import java.security.SecureRandom;

public class SecureRandomService {

    private final SecureRandom secureRandom;

    public SecureRandomService() {
        this.secureRandom = new SecureRandom();
    }


    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}

