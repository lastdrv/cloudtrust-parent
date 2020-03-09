package io.cloudtrust.crypto;

import io.cloudtrust.exception.CloudtrustRuntimeException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for the module
 */
public class CryptoUtil {

    private static final String DB_HMAC_KEY_ENV_VAR_NAME = "DB_HMAC_KEY";
    private static final String DB_ENCRYPTION_KEY_ENV_VAR_NAME = "DB_ENCRYPTION_KEY";

    private static final String HMAC_SHA512 = "HmacSHA512";
    private static final int IV_SIZE = 12; //size recommended by NIST

    private static byte[] DB_HMAC_KEY;
    private static byte[] DB_ENCRYPTION_KEY;

    //Avoid class instantiation
    private CryptoUtil() {
    }

    /**
     * Encrypts the given String with the AES/GCM/NoPadding algorithm.
     *
     * @param aesKey        The AES secret key with with to encrypt the data
     * @param textToEncrypt The text to encrypt
     * @return The crypted output encoded to a base64 String.
     * @throws BadPaddingException          thrown if there's a problem with the submitted data
     * @throws IllegalBlockSizeException    thrown if there's a problem with the submitted data
     * @throws UnsupportedEncodingException thrown if there's a problem with the submitted data
     */
    public static String gcmEncrypt(SecretKey aesKey, String textToEncrypt) throws BadPaddingException, IllegalBlockSizeException {
        return gcmEncryptData(aesKey, textToEncrypt.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encrypts the given byte array with the AES/GCM/NoPadding algorithm.
     *
     * @param aesKey The AES secret key with with to encrypt the data
     * @param data   The bytes to encrypt
     * @return The crypted output encoded to a base64 String.
     * @throws BadPaddingException       thrown if there's a problem with the submitted data
     * @throws IllegalBlockSizeException thrown if there's a problem with the submitted data
     */
    public static String gcmEncryptData(SecretKey aesKey, byte[] data) throws BadPaddingException, IllegalBlockSizeException {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        sr.nextBytes(iv);
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);
            byte[] cipheredText = cipher.doFinal(data);
            ByteBuffer gcmData = ByteBuffer.allocate(iv.length + cipheredText.length);
            gcmData.put(iv);
            gcmData.put(cipheredText);
            return Base64.getEncoder().encodeToString(gcmData.array());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Error in the gcm encryption algorithm parameters", e);
        }
    }

    /**
     * Decrypts the given base64-encoded string with the AES/GCM/NoPadding algorithm.
     *
     * @param aesKey        The AES secret key used to encrypt the data
     * @param encryptedData The data to decrypt, encoded in a base64 String
     * @return The decrypted data, or null if the provided data is null
     * @throws BadPaddingException       thrown if there's a problem with the submitted data
     * @throws IllegalBlockSizeException thrown if there's a problem with the submitted data
     */
    public static byte[] gcmDecryptData(SecretKey aesKey, String encryptedData) throws BadPaddingException, IllegalBlockSizeException {
        if (encryptedData == null) return null;
        ByteBuffer gcmData = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedData));
        byte[] iv = new byte[IV_SIZE];
        gcmData.get(iv);
        byte[] cipheredText = new byte[gcmData.remaining()];
        gcmData.get(cipheredText);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);
            return cipher.doFinal(cipheredText);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("Error in the gcm decryption algorithm parameters", e);
        }
    }

    /**
     * Decrypts the given String with the AES/GCM/NoPadding algorithm.
     *
     * @param aesKey        The AES secret key used to encrypt the data
     * @param encryptedText The text to encrypt, encoded in a base64 String
     * @return The decrypted plain text
     * @throws BadPaddingException       thrown if there's a problem with the submitted data
     * @throws IllegalBlockSizeException thrown if there's a problem with the submitted data
     */
    public static String gcmDecrypt(SecretKey aesKey, String encryptedText) throws BadPaddingException, IllegalBlockSizeException {
        return new String(gcmDecryptData(aesKey, encryptedText), StandardCharsets.UTF_8);
    }

    /**
     * Encrypt data that are meant to be stored encrypted into the database
     *
     * @param data data to be encrypted
     * @return base64 representation of the encrypted data
     */
    public static String encryptForDatabaseStorage(byte[] data) {
        try {
            byte[] dbEncryptionKey = getCtDatabaseSecurityKey();
            SecretKey originalKey = new SecretKeySpec(dbEncryptionKey, 0, dbEncryptionKey.length, "AES");
            return gcmEncryptData(originalKey, data);
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            throw new IllegalArgumentException("Unexpected error while encrypting data for database storage", ex);
        }
    }

    /**
     * Decrypt data that are stored encrypted into the database
     *
     * @param data base64-encoded data to be decrypted
     * @return decrypted data as a UTF-8 encoded String
     */
    public static byte[] decryptFromDatabaseStorage(String data) {
        try {
            byte[] dbEncryptionKey = getCtDatabaseSecurityKey();
            SecretKey originalKey = new SecretKeySpec(dbEncryptionKey, 0, dbEncryptionKey.length, "AES");
            return gcmDecryptData(originalKey, data);
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            throw new IllegalArgumentException("Unexpected error while encrypting data for database storage", ex);
        }
    }

    /**
     * Compute the HMAC of a given string.
     * The key is taken from the DB_HMAC_KEY environment variable
     *
     * @param input the string to HMAC
     * @return the HMAC value as a base64-encoded string
     */
    public static String computeHmacForDatabaseStorage(String input) {
        try {
            byte[] dbHmacKey = getCtDatabaseHmacKey();
            Mac sha512Hmac = Mac.getInstance(HMAC_SHA512);
            SecretKeySpec keySpec = new SecretKeySpec(dbHmacKey, HMAC_SHA512);
            sha512Hmac.init(keySpec);
            byte[] macData = sha512Hmac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(macData);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CloudtrustRuntimeException("Error while computing HMAC for database storage", e);
        }
    }

    private static byte[] getCtDatabaseSecurityKey() {
        try {
            if (DB_ENCRYPTION_KEY == null) {
                String keyB64 = System.getenv(DB_ENCRYPTION_KEY_ENV_VAR_NAME); // the key is encoded in Base64
                if (keyB64 == null) {
                    throw new IllegalStateException("Cannot load the " + DB_ENCRYPTION_KEY_ENV_VAR_NAME);
                }
                DB_ENCRYPTION_KEY = Base64.getDecoder().decode(keyB64);
            }
            return DB_ENCRYPTION_KEY;
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot load the " + DB_ENCRYPTION_KEY_ENV_VAR_NAME, ex);
        }
    }

    private static byte[] getCtDatabaseHmacKey() {
        try {
            if (DB_HMAC_KEY == null) {
                String keyB64 = System.getenv(DB_HMAC_KEY_ENV_VAR_NAME); // the key is encoded in Base64
                if (keyB64 == null) {
                    throw new IllegalStateException("Cannot load the " + DB_HMAC_KEY_ENV_VAR_NAME);
                }
                DB_HMAC_KEY = Base64.getDecoder().decode(keyB64);
            }
            return DB_HMAC_KEY;
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot load the " + DB_HMAC_KEY_ENV_VAR_NAME, ex);
        }
    }

}
