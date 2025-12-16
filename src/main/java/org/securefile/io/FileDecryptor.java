package org.securefile.io;
import org.securefile.crypto.CryptoService;
import org.securefile.crypto.KeyDerivationService;
import org.securefile.crypto.SecureRandomService;
import org.securefile.util.Constants;




import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class FileDecryptor {

    private final KeyDerivationService keyDerivationService;
    private final CryptoService cryptoService;

    public FileDecryptor() {
        this.keyDerivationService = new KeyDerivationService();
        this.cryptoService = new CryptoService();
    }


    public void decryptFile(Path inputFile, Path outputFile, char[] password) throws Exception {

        try (DataInputStream dis = new DataInputStream(Files.newInputStream(inputFile))) {

            byte[] magic = new byte[Constants.MAGIC_HEADER.length()];
            dis.readFully(magic);

            if (!Constants.MAGIC_HEADER.equals(new String(magic))) {
                throw new SecurityException("Invalid file format");
            }

            int version = dis.readInt();
            if (version != Constants.FORMAT_VERSION) {
                throw new SecurityException("Unsupported file version");
            }

            int saltLength = dis.readInt();
            byte[] salt = new byte[saltLength];
            dis.readFully(salt);

            int ivLength = dis.readInt();
            byte[] iv = new byte[ivLength];
            dis.readFully(iv);

            int cipherLength = dis.readInt();
            byte[] ciphertext = new byte[cipherLength];
            dis.readFully(ciphertext);

            SecretKey key = keyDerivationService.deriveKey(password, salt);

            byte[] plaintext = cryptoService.decrypt(ciphertext, key, iv);

            Files.write(outputFile, plaintext);

            Arrays.fill(plaintext, (byte) 0);
        }
    }
}
