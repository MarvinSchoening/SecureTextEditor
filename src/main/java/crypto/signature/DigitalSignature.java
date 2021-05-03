package crypto.signature;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.DSAParameterSpec;

/**
 * Generate and verify SHA256withDSA Digital Signature.
 *
 * @author Marvin Schöning
 */
public class DigitalSignature {
  /**
   * Returns a generated set of DSA parameters suitable for creating bit keys.
   * @param keys how many keys should be created (1024, 2048, 3072)
   * @return a DSAParameterSpec holding the generated parameters
   */
  public static DSAParameterSpec generateDsaParams(int keys)
      throws GeneralSecurityException {
    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DSA", "BC");
    paramGen.init(keys);
    AlgorithmParameters params = paramGen.generateParameters();
    return params.getParameterSpec(DSAParameterSpec.class);

  }

  /**
   * Generate a DSA key pair using specified parameters.
   *
   * @param dsaSpec the DSA parameters to use for key generation.
   * @return a DSA KeyPair
   */
  public static KeyPair generateDsaKeyPair(DSAParameterSpec dsaSpec)
      throws GeneralSecurityException {
    KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BC");

    keyPair.initialize(dsaSpec);

    return keyPair.generateKeyPair();
  }

  /**
   * Generate an encoded DSA signature using the passed in private key and
   * input data.
   *
   * @param dsaPrivate the private key for generating the signature with.
   * @param input the input to be signed.
   * @return the encoded signature
   */
  public static byte[] generateDsaSignature(
      PrivateKey dsaPrivate,
      byte[] input)
      throws GeneralSecurityException {
    Signature signature = Signature.getInstance("SHA256withDSA", "BC");
    signature.initSign(dsaPrivate);
    signature.update(input);

    return signature.sign();
  }

  /**
   * Return true if the passed in signature verifies against
   * the passed in DSA public key and input.
   *
   * @param dsaPublic    the public key of the signature creator
   * @param input        the input that was supposed to have been signed
   * @param encSignature the encoded signature
   * @return true if the signature verifies, false otherwise
   */
  public static boolean verifyDsaSignature(
      PublicKey dsaPublic,
      byte[] input,
      byte[] encSignature)
      throws GeneralSecurityException {

    Signature signature = Signature.getInstance("SHA256withDSA", "BC");
    signature.initVerify(dsaPublic);
    signature.update(input);
    return signature.verify(encSignature);
  }
}
