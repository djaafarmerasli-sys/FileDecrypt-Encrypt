package org.securefile.crypto;
import org.securefile.util.Constants;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class KeyDerivationService {

    public SecretKey deriveKey(char[] password, byte[] salt) throws Exception {

        SecretKeyFactory factory =
                SecretKeyFactory.getInstance(Constants.KDF_ALGORITHM);

        KeySpec spec = new PBEKeySpec(
                password,
                salt,
                Constants.PBKDF2_ITERATIONS,
                Constants.KEY_LENGTH
        );

        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        // Clear password from memory ASAP
        Arrays.fill(password, '\0');

        return new SecretKeySpec(keyBytes, "AES");
    }
}
