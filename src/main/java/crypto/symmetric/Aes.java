package crypto.symmetric;

import crypto.Utility;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Hex;


public class Aes {
  /**
   * Method to return a symmetric decrypted message.
   *
   * @param input          encrypted text as hex byte[]
   * @param encryptionType type that was used for encryption
   * @param blockmode      blockmode that was used for encryption
   * @param padding        padding that was used for encryption
   * @param key            secretKey that was used for encryption
   * @param iv             iv that was used for encryption, null if none was used
   * @return decrypted message
   */
  public static byte[] decrypt(
          byte[] input,
          String encryptionType,
          String blockmode,
          String padding,
          SecretKey key,
          byte[] iv
  )
          throws Exception {

    // Generate Cipher, load key and change input to hex
    Cipher cipher = Utility.generateCipher(encryptionType, blockmode, padding);

    // Init Cipher
    if (!Utility.blockmodeWithoutIV.contains(blockmode)) {
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    } else {
      cipher.init(Cipher.DECRYPT_MODE, key);
    }

    // set cipherText length
    byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

    // Iterate through the full input
    int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
    ctLength += cipher.doFinal(cipherText, ctLength);

    //Return decrypted string
    return Arrays.copyOf(cipherText, ctLength);
  }

  /**
   * Method to return a symmetric encrypted message, the used key and iv.
   *
   * @param input          plainText for encryption as byte[]
   * @param encryptionType e.g. AES
   * @param blockmode      e.g. ECB
   * @param padding        e.g. PKCS5Padding
   * @param iv             iv as byte[] if used, else null
   * @return encrypted message as byte[]
   * @throws Exception Throws Exceptions
   */
  public static byte[] encrypt(
          byte[] input,
          String encryptionType,
          SecretKey key,
          String blockmode,
          String padding,
          byte[] iv)
          throws Exception {

    // Init Cipher
    Cipher cipher = Utility.generateCipher(encryptionType, blockmode, padding);
    if (!Utility.blockmodeWithoutIV.contains(blockmode)) {
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }

    //Return decrypted string
    return cipher.doFinal(input);
    // Save cipherText as hexString into return array
  }
}
