package crypto.students;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.util.Base64;

import org.apache.log4j.Logger;

public class StreamCipher {

	private static Logger log = Logger.getLogger(StreamCipher.class);

	private BigInteger key;
	private BigInteger prime;
	private BigInteger p1;
	private BigInteger p2;
	private BigInteger r_i;

	public StreamCipher(BigInteger share, BigInteger prime, BigInteger p,
			BigInteger q) {
		this.key = share; // shared key from DH
		this.prime = prime; // DH prime modulus
		this.p1 = Supplementary.deriveSuppementaryKey(share, p);
		this.p2 = Supplementary.deriveSuppementaryKey(share, q);
		this.r_i = Supplementary.parityWordChecksum(this.key); // shift register
	}

	/***
	 * Updates the shift register for XOR-ing the next byte.
	 */
	public void updateShiftRegister() {
		// log.error("You must implement this function!");
		r_i = p1.multiply(r_i).add(p2).mod(this.prime);
	}

	/***
	 * This function returns the shift register to its initial position
	 */
	public void reset() {
		// log.error("You must implement this function!");
		this.r_i = Supplementary.parityWordChecksum(this.key);
	}

	/***
	 * Gets N numbers of bits from the MOST SIGNIFICANT BIT (inclusive).
	 * 
	 * @param value
	 *            Source from bits will be extracted
	 * @param n
	 *            The number of bits taken
	 * @return The n most significant bits from value
	 */
	private byte msb(BigInteger value, int n) {
		// log.error("You must implement this function!");
		//byte[] msg = value.toByteArray();
		if(value.bitLength() <= 8) {
			return value.byteValue();
		}
		BigInteger msg = value.shiftRight(value.bitLength() - n);
		return msg.byteValue();
	}

	/***
	 * Takes a cipher text/plain text and decrypts/encrypts it.
	 * 
	 * @param msg
	 *            Either Plain Text or Cipher Text.
	 * @return If PT, then output is CT and vice-versa.
	 */
	private byte[] _crypt(byte[] msg) {
		// log.error("You must implement this function!");
		for (int i = 0; i < msg.length; i++) {			
			msg[i] = (byte) (msg[i] ^ (msb(((p1.multiply(r_i)).add(p2)).mod(this.prime), 8)));
			updateShiftRegister();
		}
		return msg;
	}

	// -------------------------------------------------------------------//
	// Auxiliary functions to perform encryption and decryption //
	// -------------------------------------------------------------------//
	public String encrypt(String msg) {
		// input: plaintext as a string
		// output: a base64 encoded ciphertext string
		log.debug("line to encrypt: [" + msg + "]");
		String result = null;
		try {
			byte[] asArray = msg.getBytes("UTF-8");
			result = Base64.getEncoder().encodeToString(_crypt(asArray));
			log.debug("encrypted text: [" + result + "]");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return result;
	}

	public String decrypt(String msg) {
		// input: a base64 encoded ciphertext string
		// output: plaintext as a string
		log.debug("line to decrypt (base64): [" + msg + "]");
		String result = null;
		try {
			byte[] asArray = Base64.getDecoder().decode(msg.getBytes("UTF-8"));
			result = new String(_crypt(asArray), "UTF-8");
			log.debug("decrypted text; [" + result + "]");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	public static void main(String []args) {
		StreamCipher s = new StreamCipher(new BigInteger("4"), new BigInteger("11"), new BigInteger("3"), new BigInteger("5"));
		//System.out.println(msb(new BigInteger("13892949480140891204"), 8));
		//System.out.println(s.encrypt(""));
		//System.out.println(Supplementary.parityWordChecksum(new BigInteger("11380312415897726212538720767584623938377542218843650885786488543557849920563944820657401556147072220807050423844611527817088743264179887246035449031879964033048917437051768727745163996083995699396309860629605332639267450328379289961205789359923142431676348109877819086396004913235006262427231898532203764657706261780748597526471127787542155628754978941021278802504747939847153450812209928520258539639347968927907337576400038705453704498741239631581573919339705649004208586949422810873621196157474272177586468236634536851618181572350294408509526514361027546939234421045026063811415872877733865949984217287267027217419")));
	}
}
