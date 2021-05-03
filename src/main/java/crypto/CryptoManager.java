package crypto;

import crypto.signature.DigitalSignature;
import crypto.symmetric.Aes;
import crypto.symmetric.Gcm;
import crypto.pbe.Pbe;
import crypto.verification.Hash;
import crypto.verification.Macs;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.encoders.Hex;

/**
 * Handles input from Editor App.
 * Defines which methods should be called from given input
 *
 * @author Marvin Schöning
 */
public class CryptoManager {

  private final int keySize;
  private final String input;
  private final String encryptionType;
  private final String blockmode;
  private final String padding;
  private final String digestName;
  private final String hashOrMac;
  private final String signatureString;
  private final String password;
  private final String salt;
  private final String[] keyString;

  private static int COST_PARAMETER = 32768;
  private static int BLOCKSIZE = 8;
  private static int PARALLELIZATION_PARAM = 1;


  /**
   * Constructor for encryption.
   *
   * @param input          text to encrypt
   * @param encryptionType e.g. "AES"
   * @param blockmode      e.g. CBC or ECB
   * @param padding        e.g. PKCS7Padding
   * @param digestName     e.g. SHA-256
   * @param keySize        e.g. 256
   * @param password       user password
   */
  public CryptoManager(
          String input, String encryptionType,
          String blockmode, String padding,
          String digestName, int keySize,
          String password) {
    this.encryptionType = encryptionType;
    this.blockmode = blockmode;
    this.padding = padding;
    this.input = input;
    this.keySize = keySize;
    this.keyString = null;
    this.digestName = digestName;
    this.hashOrMac = null;
    this.signatureString = null;
    this.password = password;
    this.salt = null;
  }

  /**
   * Constructor for decryption.
   *
   * @param input           encrytped text
   * @param encryptionType  encryptionType e.g. "AES"
   * @param blockmode       CBC/ECB/OBF etc
   * @param padding         NoPadding/PKCS7Padding/ZeroBytePadding
   * @param digestName      hash or mac algorithm name
   * @param hashOrMac       hash or mac value from algorithm
   * @param signatureString signature string
   * @param keyArray        [0] encryption key, [1] iv, [2] macKey, [3] signature public key
   * @param password        password that was used, ""/null if no password was used
   * @param salt            salt that was used for the password
   */
  public CryptoManager(
          String input,
          String encryptionType,
          String blockmode,
          String padding,
          String digestName,
          String hashOrMac,
          String signatureString,
          String[] keyArray,
          String password,
          String salt
  ) {
    this.encryptionType = encryptionType;
    this.blockmode = blockmode;
    this.padding = padding;
    this.input = input;
    this.keySize = 0;
    this.keyString = Arrays.copyOf(keyArray, 7);
    this.digestName = digestName;
    this.hashOrMac = hashOrMac;
    this.signatureString = signatureString;
    this.password = password;
    this.salt = salt;
  }

  /**
   * Encrypt with class parameters.
   *
   * @return [0] key,
   [1] encrypted message,
   [2] iv,
   [3] hashOrMac,
   [4] macKey,
   [5] signature,
   [6] signature public key,
   [7] salt
   */
  public String[] encrypt() throws Exception {
    int arrayLength = 8;
    String[] returnArray = new String[arrayLength];

    // Generate Key depending on password
    SecretKey key;
    if (password.equals("")) {
      key = Utility.generateKey(encryptionType, keySize);
      returnArray[0] = Hex.toHexString(key.getEncoded());

      //Encrypt
      String[] encryptArray;
      if (blockmode.equals("GCM") || blockmode.equals("CCM")) {
        encryptArray = Gcm.gcmEncrypt(key, input.getBytes(StandardCharsets.UTF_8));
        returnArray[1] = encryptArray[0];
        returnArray[2] = encryptArray[1];
      } else {

        byte[] iv = null;
        if (!blockmode.equals("ECB")) {
          SecureRandom random = new SecureRandom();
          iv = new byte[16];
          random.nextBytes(iv);
          returnArray[2] = Hex.toHexString(iv);
        }
        returnArray[1] =
                Hex.toHexString(Aes.encrypt(input.getBytes(StandardCharsets.UTF_8), encryptionType, key, blockmode, padding, iv));

      }
    } else {
      if (encryptionType.equals("AES256, GCM, SCrypt")) {

        byte[] saltArray = Hex.encode(Utility.getNextSalt());
        byte[] scryptKeyArray = SCrypt.generate(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()),
                saltArray, COST_PARAMETER, BLOCKSIZE, PARALLELIZATION_PARAM, 256 / 8);

        key = new SecretKeySpec(scryptKeyArray, 0, scryptKeyArray.length, encryptionType);

        //Encrypt
        String[] encryptArray;
        encryptArray = Gcm.gcmEncrypt(key, input.getBytes(StandardCharsets.UTF_8));
        returnArray[1] = encryptArray[0];
        returnArray[2] = encryptArray[1];
        returnArray[7] = Hex.toHexString(saltArray); // Salt
      } else {
        //Encrypt
        String[] encryptArray = Pbe.encrypt(input, encryptionType, password);
        returnArray[1] = encryptArray[0];
        returnArray[7] = encryptArray[1];
      }
    }


    // Save hash
    if (digestName.equals("SHA-256")) {
      byte[] hash = Hash.computeDigest(digestName, Hex.decode(returnArray[1]));
      returnArray[3] = Hex.toHexString(hash);
    } else {
      SecretKey macKey;
      if (digestName.equals("AESCMAC")) {
        macKey = Utility.generateKey("AES");
      } else {
        macKey = Utility.generateKey("HmacSHA256");
      }

      byte[] mac = Macs.computeMac(digestName, macKey, Hex.decode(returnArray[1]));
      returnArray[3] = Hex.toHexString(mac);
      returnArray[4] = Hex.toHexString(macKey.getEncoded());
    }

    // Apply signature
    KeyPair kp = DigitalSignature.generateDsaKeyPair(DigitalSignature.generateDsaParams(2048));
    byte[] signature = DigitalSignature.generateDsaSignature(
            kp.getPrivate(),
            Hex.decode(returnArray[1])
    );
    returnArray[5] = Hex.toHexString(signature);
    returnArray[6] = Hex.toHexString(kp.getPublic().getEncoded());
    return returnArray;
  }

  /**
   * Decrypt with class parameters.
   *
   * @return decrypted message as string
   * @throws Exception Exceptions
   */
  public String decrypt() throws Exception {

    byte[] byteInput = Hex.decode(input);

    // Check digital signature
    PublicKey publicKey = KeyFactory.getInstance("DSA").generatePublic(
            new X509EncodedKeySpec(Hex.decode(keyString[3]))
    );

    DigitalSignature.verifyDsaSignature(publicKey, byteInput, Hex.decode(signatureString));

    // Check Hash or Mac
    if (digestName.equals("SHA-256")) {
      byte[] hash = Hash.computeDigest(digestName, byteInput);
      if (!Hex.toHexString(hash).equals(hashOrMac)) {
        throw new Exception("Hash not equal");
      }
    } else {
      SecretKey macKey;
      if (digestName.equals("HmacSHA256")) {
        macKey = Utility.loadKey(keyString[2], digestName);
      } else {
        macKey = Utility.loadKey(keyString[2], encryptionType);
      }
      byte[] mac = Macs.computeMac(digestName, macKey, byteInput);
      if (!Hex.toHexString(mac).equals(hashOrMac)) {
        throw new Exception("Mac not equal");
      }
    }

    // Generate IV if used
    byte[] iv;
    if (keyString[1] == null) {
      iv = null;
    } else {
      iv = Utility.loadIV(keyString[1]);
    }

    //Generate Key depending on password
    SecretKey key;
    if (password.equals("")) {
      key = Utility.loadKey(keyString[0], encryptionType);
      // Decrypt
      if (blockmode.equals("GCM") || blockmode.equals("CCM")) {
        return new String(Gcm.gcmDecrypt(key, iv, byteInput), StandardCharsets.UTF_8);
      }
      return new String(Aes.decrypt(
              byteInput,
              encryptionType,
              blockmode,
              padding,
              key,
              iv), StandardCharsets.UTF_8);
    } else {
      if (encryptionType.equals("AES256, GCM, SCrypt")) {
        byte[] scryptKeyArray = SCrypt.generate(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()),
                Hex.decode(salt), COST_PARAMETER, BLOCKSIZE, PARALLELIZATION_PARAM, 256 / 8);

        key = new SecretKeySpec(scryptKeyArray, 0, scryptKeyArray.length, "AES");
        return new String(Gcm.gcmDecrypt(key, iv, byteInput), StandardCharsets.UTF_8);

      } else {
        return Pbe.decrypt(
                byteInput,
                Hex.decode(salt),
                encryptionType,
                password);
      }
    }
  }
}


