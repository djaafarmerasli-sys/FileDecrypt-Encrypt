package org.securefile.util;

public final class Constants {



    public static final String MAGIC_HEADER = "SFE";


    public static final int FORMAT_VERSION = 1;




    public static final int SALT_LENGTH = 16;


    public static final int IV_LENGTH = 12;


    public static final int AUTH_TAG_LENGTH = 128;



    // Symmetric encryption algorithm
    public static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    // Password-based key derivation
    public static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";




    public static final int PBKDF2_ITERATIONS = 100_000;


    public static final int KEY_LENGTH = 256;


    private Constants() {
        throw new AssertionError("Constants class should not be instantiated");
    }
}
