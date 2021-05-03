package crypto;

import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class UtilityTest {

  Utility util = new Utility();

  @Test
  void generateSymmetricKeyAESTest() {

    //Test all Key sizes
    int expectedLength128 = 16;
    int expectedLength192 = 24;
    int expectedLength256 = 32;
    String expectedAlgorithm = "AES";

    SecretKey key128 = null;
    SecretKey key192 = null;
    SecretKey key256 = null;
    try {
      key128 = Utility.generateKey(expectedAlgorithm, 128);
      key192 = Utility.generateKey(expectedAlgorithm, 192);
      key256 = Utility.generateKey(expectedAlgorithm, 256);
    } catch (Exception e) {
      e.printStackTrace();
    }

    byte[] kb128 = key128.getEncoded();
    byte[] kb192 = key192.getEncoded();
    byte[] kb256 = key256.getEncoded();

    assertEquals(expectedLength128, kb128.length);
    assertEquals(expectedAlgorithm, key128.getAlgorithm());

    assertEquals(expectedLength192, kb192.length);
    assertEquals(expectedAlgorithm, key192.getAlgorithm());

    assertEquals(expectedLength256, kb256.length);
    assertEquals(expectedAlgorithm, key256.getAlgorithm());
  }

  @Test
  void generateSymmetricKeyDESTest() {
    int expectedLength = 8;
    String expectedAlgorithm = "DES";

    SecretKey key = null;
    try {
      key = Utility.generateKey(expectedAlgorithm);
    } catch (Exception e) {
      e.printStackTrace();
    }

    byte[] kb = key.getEncoded();

    assertEquals(expectedLength, kb.length);
    assertEquals(expectedAlgorithm, key.getAlgorithm());
  }

  @Test
  void loadKeyTest() {
    byte[] expectedKeyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
    SecretKeySpec key = new SecretKeySpec(expectedKeyBytes, "AES");

    SecretKey actualKey = Utility.loadKey(Hex.toHexString(key.getEncoded()), "AES");

    //Check equal on string, because byteArrays have different pointer
    assertArrayEquals(expectedKeyBytes, actualKey.getEncoded());
  }

  @Test
  void loadIVTest() {
    byte[] expectedKeyBytes = Hex.decode("cf626d319184b648a0fc316b89d68c27");
    byte[] actualKey = Utility.loadIV("cf626d319184b648a0fc316b89d68c27");

    //Check equal on string, because byteArrays have different pointer
    assertArrayEquals(expectedKeyBytes, actualKey);
  }

  @Test
  void getCipherTest() {
    try {
      String expectedAlgorithm = "AES/ECB/NoPadding";
      Provider expectedProvider = Security.getProvider("BC");
      int expectedBlockSize = 16;

      Cipher cipher = Utility.generateCipher("AES", "ECB", "NoPadding");

      assertEquals(expectedAlgorithm, cipher.getAlgorithm());
      assertEquals(expectedProvider, cipher.getProvider());
      assertEquals(expectedBlockSize, cipher.getBlockSize());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}