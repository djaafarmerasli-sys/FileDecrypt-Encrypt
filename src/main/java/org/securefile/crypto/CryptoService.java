package org.securefile.crypto;

import org.securefile.util.Constants;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class CryptoService {

    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(Constants.CIPHER_ALGORITHM);

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(Constants.AUTH_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(Constants.CIPHER_ALGORITHM);

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(Constants.AUTH_TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        return cipher.doFinal(ciphertext);
    }
}
