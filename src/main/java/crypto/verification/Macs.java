package crypto.verification;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Class for generating H/MAC.
 * @author Marvin Schöning
 */
public class Macs {
  /**
   * Return a MAC computed over data using the passec in Mac algorithm
   * type algorithm.
   *
   * @param algorithm the name of the MAC algorithm
   * @param key an appropriate secret key for the MAC algorithm
   * @param data the input for the MAC function
   * @return the computed mac
   */
  public static byte[] computeMac(
      String algorithm,
      SecretKey key,
      byte[] data)
      throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {

    Mac mac = Mac.getInstance(algorithm, "BC");

    mac.init(key);

    mac.update(data);

    return mac.doFinal();

  }
}
