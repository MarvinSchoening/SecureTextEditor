package crypto.pbe;

import crypto.Utility;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.util.encoders.Hex;


public class Pbe {
  /**
   * Method to return a symmetric decrypted message.
   *
   * @param input          encrypted text
   * @param encryptionType type that was used for encryption
   * @return decrypted message
   */
  public static String decrypt(
          byte[] input,
          byte[] salt,
          String encryptionType,
          String password
  )
          throws Exception {

    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 100);

    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(encryptionType);
    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

    // Generate Cipher, load key and change input to hex
    Cipher cipher = Cipher.getInstance(encryptionType, "BC");

    // Init Cipher
    cipher.init(Cipher.DECRYPT_MODE, secretKey);

    // set cipherText length
    byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

    // Iterate through the full input
    int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
    ctLength += cipher.doFinal(cipherText, ctLength);

    //Return decrypted string
    return new String(Arrays.copyOfRange(cipherText, 0, ctLength), StandardCharsets.UTF_8);
  }

  /**
   * Method to return a symmetric encrypted message, the used key and iv.
   *
   * @param input          plainText for encryption
   * @param encryptionType e.g. AES
   * @return [0] = encrypted and encoded message, [1] = salt
   * @throws Exception Throws Exceptions
   */
  public static String[] encrypt(
          String input,
          String encryptionType,
          String password)
          throws Exception {

    // Return variable
    String[] encryptedArray = new String[2];

    byte[] salt = Hex.encode(Utility.getNextSalt());
    encryptedArray[1] = Hex.toHexString(salt); // Salt

    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 100);

    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(encryptionType);
    SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

    // Init Cipher
    Cipher cipher = Cipher.getInstance(encryptionType, "BC");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    // Convert input into a byte[] byteInput for encryption
    byte[] byteInput = input.getBytes(StandardCharsets.UTF_8);

    // set cipherText length
    byte[] cipherText = new byte[cipher.getOutputSize(byteInput.length)];

    // Iterate through the full text
    int ctLength = cipher.update(byteInput, 0, byteInput.length, cipherText, 0);
    cipher.doFinal(cipherText, ctLength);

    // Save cipherText as hexString into return array
    encryptedArray[0] = Hex.toHexString(cipherText);

    return encryptedArray;
  }
}
