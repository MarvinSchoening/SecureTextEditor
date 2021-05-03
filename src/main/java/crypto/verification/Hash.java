package crypto.verification;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Hash {

  /**
   * Return a digest computed over data using the passed in algorithm digestName.
   *
   * @param digestName the name of the digest algorithm
   * @param data       the input for the digest function
   * @return the computed message digest
   */
  public static byte[] computeDigest(
          String digestName,
          byte[] data)
          throws NoSuchProviderException, NoSuchAlgorithmException {

    MessageDigest digest = MessageDigest.getInstance(digestName, "BC");

    digest.update(data);

    return digest.digest();
  }
}
