package crypto;

import crypto.symmetric.Aes;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class NISTKnownAnswerTest {

  void testAesEncrypt(byte[] expectedPlainText, byte[] expectedCipherText, byte[] key, byte[] iv, String blockmode) {
    try {
      byte[] encryptArray = Aes.encrypt(expectedPlainText, "AES", new SecretKeySpec(key, "AES"), blockmode, "NoPadding", iv);

      assertArrayEquals(expectedCipherText, encryptArray);
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
  }

  void testAesDecrypt(byte[] expectedPlainText, byte[] expectedCipherText, byte[] key, byte[] iv, String blockmode) {
    try {
      byte[] decrypted = Aes.decrypt(expectedCipherText, "AES", blockmode, "NoPadding", new SecretKeySpec(key, "AES"), iv);
      assertArrayEquals(expectedPlainText, decrypted);
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }
  }

  @Test
  void AES_CBC() {
    byte[] expectedCipherText;
    byte[] expectedPlainText;
    byte[] key;
    byte[] iv;
    String blockmode = "CBC";

    iv = Hex.decode("000102030405060708090a0b0c0d0e0f");

    // 128 Bit
    key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("7649abac8119b246cee98e9b12e9197d");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 192 Bit
    key = Hex.decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("4f021db243bc633d7178183a9fa071e8");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 256 Bit
    key = Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

  }

  @Test
  void AES_ECB() {
    byte[] expectedCipherText;
    byte[] expectedPlainText;
    byte[] key;
    byte[] iv;
    String blockmode = "ECB";

    iv = null;
    // 128 Bit
    key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("3ad77bb40d7a3660a89ecaf32466ef97");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 192 Bit
    key = Hex.decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    expectedPlainText = Hex.decode("ae2d8a571e03ac9c9eb76fac45af8e51");
    expectedCipherText = Hex.decode("974104846d0ad3ad7734ecb3ecee4eef");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 256 Bit
    key = Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 ");
    expectedPlainText = Hex.decode("30c81c46a35ce411e5fbc1191a0a52ef");
    expectedCipherText = Hex.decode("b6ed21b99ca6f4f9f153e7b1beafed1d");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

  }

  @Test
  void AES_OFB() {
    byte[] expectedCipherText;
    byte[] expectedPlainText;
    byte[] key;
    byte[] iv;
    String blockmode = "OFB";

    iv = Hex.decode("000102030405060708090a0b0c0d0e0f");
    // 128 Bit
    key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("3b3fd92eb72dad20333449f8e83cfb4a");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 192 Bit
    key = Hex.decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("cdc80d6fddf18cab34c25909c99a4174");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

    // 256 Bit
    key = Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    expectedPlainText = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    expectedCipherText = Hex.decode("dc7e84bfda79164b7ecd8486985d3860");
    testAesEncrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);
    testAesDecrypt(expectedPlainText, expectedCipherText, key, iv, blockmode);

  }

}
