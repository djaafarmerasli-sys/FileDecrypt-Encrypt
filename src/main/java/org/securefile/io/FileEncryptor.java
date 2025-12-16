package org.securefile.io;
import org.securefile.crypto.CryptoService;
import org.securefile.crypto.KeyDerivationService;
import org.securefile.crypto.SecureRandomService;
import org.securefile.util.Constants;



import javax.crypto.SecretKey;
import java.io.DataOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileEncryptor {
    private final SecureRandomService randomService;
    private final KeyDerivationService keyDerivationService;
    private final CryptoService cryptoService;

    public FileEncryptor() {
        this.randomService = new SecureRandomService();
        this.keyDerivationService = new KeyDerivationService();
        this.cryptoService = new CryptoService();
    }

    public void encryptFile(Path inputFile, Path outputFile, char[] password) throws Exception {

        byte[] plaintext = Files.readAllBytes(inputFile);

        byte[] salt = randomService.generateRandomBytes(Constants.SALT_LENGTH);
        byte[] iv = randomService.generateRandomBytes(Constants.IV_LENGTH);

        SecretKey key = keyDerivationService.deriveKey(password, salt);

        byte[] ciphertext = cryptoService.encrypt(plaintext, key, iv);

        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(outputFile))) {

            dos.writeBytes(Constants.MAGIC_HEADER);
            dos.writeInt(Constants.FORMAT_VERSION);

            dos.writeInt(salt.length);
            dos.write(salt);

            dos.writeInt(iv.length);
            dos.write(iv);

            dos.writeInt(ciphertext.length);
            dos.write(ciphertext);
        }
    }
}
