package crypto.students;

import java.math.BigInteger;
import java.util.Random;

import org.apache.log4j.Logger;

/***
 * In this class, all the candidates must implement their own math and crypto
 * functions required to solve any calculation and encryption/decryption task
 * involved in this project.
 * 
 * @author pabloserrano
 *
 */
public class DHEx {

	// debug logger
	private static Logger log = Logger.getLogger(DHEx.class);

	private static Random rnd = new Random();

	/**
	 * Randomly generate the private key for client.
	 * 
	 * @param size
	 *            the given bitlength
	 * @return privateKey
	 */
	public static BigInteger createPrivateKey(int size) {
		// randomly generate a private key no longer than given size
		BigInteger privateKey = BigInteger.probablePrime(size, rnd);
		return privateKey;
	}

	/**
	 * Returns a pair of keys including private key and public key of client.
	 * 
	 * @param generator
	 *            a public big integer
	 * @param prime
	 * @param skClient
	 *            private key from client
	 * @return private key and public key
	 */
	public static BigInteger[] createDHPair(BigInteger generator,
			BigInteger prime, BigInteger skClient) {
		BigInteger[] pair = new BigInteger[2];
		// log.debug("You must implement this function!");
		// pair[0] represents private key
		pair[0] = skClient;
		// pair[1] represents public key, pk = generator^2(mod) prime.
		pair[1] = modExp(generator, skClient, prime);
		return pair;
	}

	/**
	 * Returns the shared key calculated by sk, pk from client and prime
	 * 
	 * @param pk
	 *            public key from client
	 * @param sk
	 *            private key from client
	 * @param prime
	 * @return shared key
	 */
	public static BigInteger getDHSharedKey(BigInteger pk, BigInteger sk,
			BigInteger prime) {
		BigInteger shared = modExp(pk, sk, prime);
		// log.debug("You must implement this function!");
		return shared;
	}

	/**
	 * This function is to calculate a^b(mod c). Assume the result is 1 from the
	 * beginning. Then multiplies "base" "exp" times. Because "exp" might be a
	 * large number. To simplify the algorithm, we can do: if "exp" is even,
	 * then let exp = exp/2, base = base^2; if "exp" is odd, then let exp =
	 * exp-1, result = result * base; To save the space for the result, each
	 * time do the "multiply", do "mod" at the same time.
	 * 
	 * @param base
	 * @param exp
	 * @param modulo
	 * @return result
	 */
	public static BigInteger modExp(BigInteger base, BigInteger exp,
			BigInteger modulo) {
		// log.debug("You must implement this function!");
		BigInteger result = BigInteger.ONE;
		while (exp.compareTo(BigInteger.ZERO) == 1) {
			if ((exp.mod(new BigInteger("2"))).equals(BigInteger.ONE)) {
				result = (result.multiply(base)).mod(modulo);
			}
			base = (base.multiply(base)).mod(modulo);
			exp = exp.divide(new BigInteger("2"));
		}
		log.debug("modExp result is " + result.mod(modulo));
		return result.mod(modulo);
	}
}
