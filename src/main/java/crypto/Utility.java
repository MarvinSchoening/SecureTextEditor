package crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

/**
 * Utility Class for generating and loading keys and generating cipher to reduce code duplication.
 *
 * @author Marvin Schöning
 */
public class Utility {

  public static final List<String> blockmodeWithoutIV =
          Collections.unmodifiableList(Arrays.asList("ECB"));
  private static final Random RANDOM = new SecureRandom();

  /**
   * Generates an symmetric key with a given keySize.
   *
   * @param encryptionType e.g. AES
   * @param keySize        must match blocksize e.g. 64 for DES or 128/192/256 for AES
   * @return Returns a SecretKey created by KeyGenerator with given Keysize
   */
  public static SecretKey generateKey(String encryptionType, int keySize) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(encryptionType, "BC");
    keyGen.init(keySize);
    return keyGen.generateKey();
  }

  /**
   * Generates an symmetric key with standard keysize of encryptionType.
   *
   * @param encryptionType e.g. AES
   * @return Returns a SecretKey created by KeyGenerator
   */
  public static SecretKey generateKey(String encryptionType) throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(encryptionType, "BC");
    return keyGen.generateKey();
  }

  /**
   * Decodes a key string to key bytes and returns a SecretKey based on the encryption type.
   *
   * @param keyString      keyString as hexString
   * @param encryptionType e.g. AES
   * @return new SecretKey
   */
  public static SecretKey loadKey(String keyString, String encryptionType) {
    byte[] keyBytes = Hex.decode(keyString);
    return new SecretKeySpec(keyBytes, 0, keyBytes.length, encryptionType);
  }

  /**
   * Decodes a hex string and returns the resulting key bytes, used for IV.
   *
   * @param ivString as hexString
   * @return byte[] iv as byte[]
   */
  public static byte[] loadIV(String ivString) {
    return Hex.decode(ivString);
  }

  /**
   * Generates a Cipher Object.
   *
   * @param encryptionType e.g. AES
   * @param blockmode      e.g. CBC
   * @param padding        e.g. PKCS5Padding
   * @return Returns a Cipher object with given parameters
   * @throws Exception NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
   */
  public static Cipher generateCipher(String encryptionType, String blockmode, String padding)
      throws Exception {
    String encryptionString = encryptionType + "/" + blockmode + "/" + padding;
    return Cipher.getInstance(encryptionString, "BC");
  }

  /**
   * Returns a random salt to be used to hash a password.
   *
   * @return a 16 bytes random salt
   */
  public static byte[] getNextSalt() {
    byte[] salt = new byte[16];
    RANDOM.nextBytes(salt);
    return salt;
  }
}
