package crypto.symmetric;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.util.encoders.Hex;

public class Gcm {
  /**
   * Encrypt the passed in data pText using GCM with the passed in parameters.
   *
   * @param key       secret key to use.
   * @param plainText the plain text input to the cipher.
   * @return [0] = cipherText, [1] = iv
   */
  public static String[] gcmEncrypt(
          SecretKey key,
          byte[] plainText)
          throws Exception {
    String[] encryptedArray = new String[2];
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

    SecureRandom random = new SecureRandom();
    byte[] iv = new byte[cipher.getBlockSize()];
    random.nextBytes(iv);

    encryptedArray[1] = new String(Hex.encode(iv), StandardCharsets.UTF_8);

    GCMParameterSpec spec = new GCMParameterSpec(128, iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, spec);

    encryptedArray[0] = Hex.toHexString(cipher.doFinal(plainText));

    return encryptedArray;
  }

  /**
   * Dencrypt the passed in data cipherText using GCM with the passed in parameters.
   *
   * @param key        secret key to use.
   * @param iv         iv to use
   * @param cipherText the cipherText text input to the cipher.
   * @return decrypted message
   */
  public static byte[] gcmDecrypt(SecretKey key,
                                   byte[] iv,
                                   byte[] cipherText)
          throws Exception {

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

    GCMParameterSpec spec = new GCMParameterSpec(128, iv);

    cipher.init(Cipher.DECRYPT_MODE, key, spec);

    return cipher.doFinal(cipherText);
  }
}
