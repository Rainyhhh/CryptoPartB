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
		// ri = (p1 * ri−1 + p2)
		this.r_i = (p1.multiply(r_i).add(p2)).mod(this.prime);
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
		// if value < 2^8 - 1, return value
		if(value.compareTo(new BigInteger("2").pow(n).subtract(BigInteger.ONE)) < 0) {
			return value.byteValue();
		}
		// if value > 2^8 - 1, >>> length - n
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
			msg[i] = (byte) (msg[i] ^ msb(this.r_i, 8));
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
	
//	public static void main(String[] args) {
//		StreamCipher s = new StreamCipher(new BigInteger("4"), new BigInteger("11"), new BigInteger("3"), new BigInteger("5"));
//		s.decrypt("fypid2xjcm9nWGFwKjsnXWpzKk5meSQ5NSU4Njw5ND01MygqNTkyNioxNzExKi0nYGYkMDY+ODw9OD05MDI6MzU2PDo5PCUgb25cdHR2KjsnPDs+MjY+ODQ6NTU5MDAyMT85JiQjcWx6cig5JUdrZ2UlZG10ZGppZyUo45ysICoocGh1dmtkJzMgOmsjb3JhbjwnYXZyejkoL3B/aHF9Z3QkYGhtK2xucmduaWtnKGFqbHNqYGYkKnFibDkqb2pvbWpmbHAiOlx2bH12Y3gjYW92KEBrbXBpY2c7L2U2IykrdnR/bWRhcG1lJzNkZ2ZwYiwmYW9ae2d2ZnpYdGtXcnFodnN5XG5kJjJvcGVuKihqaV92bXFpcF1yZVx0dGV8dHZWa2JVcHNyJjJvcGVuKihqaV92bXFpcF1yZVxyc2F6XmxtIDxkdmtsKCpoa1ZwY3pvfl9wZ15wemd0VWpjX3d8cyczbHNmbysibWZed2xyanNcc29be2J3bGdoVW1mbWEqO2t8bmomIXJzYXojP3Igb24hPTc3PzMyODExJiFuZFt7dXcrOCQ9MDAyMzkyMisuJGRiamUmMiNEZGBjeCNFcnFmcueVgCQmIXRjdm1ka1ZsZ2dmJTomS25pZnd0W3ZiZWpJQyclIGplYGZ0bWdvJzMgVUtNJ0FKXE5LQE0qKldCWEVbIykrd3RmIT1ucWRtKStmY3lgdWl0fGhqZyA8KEBITEtdUyVYd2NvbSdCKigiTWhrdCpQc3loYXJxKWtoKndvZSRFYG5gbGEkI04gSEdXQClBSUZMVSEkSnglSGx/Kk5iYWp7LyVIbH9+a25uYyhIdilSaXlwbmJobS8nJSB2eGxzZWd8ZGErOGBrb3RlKCp3YHtrYGNmYyI+bmBpemcqKGVobGhndmB7cVlpbHJucCo7Njg7KihldWlhZmV2VmFpf21zIj48NTclIGpjcHNlYFdianxscig5NjIoKmdkf21zeGpzZXdXYmp8bHIoOTQ3PCQjdn1jcn9wYnNba25wZ3YkMDY1NDMkI2Z7Z2d+ZmNfZXwjPytRZ34jVGV0KDA3KTA2MDE+OjQ/IS45MjY6IzUwNDEjKSt3cmlcaGZie2RxKzgrOzs3MDQkI3Fgb2NVeWhuYSo7J0pnaH5xZmwkXGhobCIuX1AnJiRLYGtoZmcjISsiY21uWmxsZ2hvYmQmMnV3fGcqKG9mbmMqOydsbCQmIWRvanxzbGt3cmVxdF9hZmBnZWdiKDlhYWh7ZCkra3VVd3VhanttZH1tdCg5YWFoe2QpK3J0ZWVubGFXY2RqaWF4bHJuYFdiamVtdCg5JTA0ODE1OSAqKHN1b2JhbWBWYGdpaGBya31vYVZra2tkYl9xem0nMyBufnd3OisnYGd6LHJ9ampnKmtuaCZra2tkYnMrfGlgZGd1JXdvZWltMDEmYGEkZG5mJiQjdXttYGNvYl9maWJubnBpf21jX21lYGJsXXN4b1hocHxxdis4JGJ3c3B3Mi4qaGB1JHdwaWlvL2ZmbyljbmZnYXsucWFna29wKHRsbWxgODYpaGQpZ21uIykrcnRlZW5sYVdjZGppYXhscm5gV3VsZWckMGVmbHdtLSd5cGlsamtlW2Roa2JdZWVvaHImMiM1SzY2PjMlLCZ4c2pva2pvXHRpYG1jZHtdZGVxY2V2V2JqZW10KDklMDQ4MTU5ICooc3VvYmFtYFZxb25mZWF2V2dsZW5ZaWxrb3YqOyc5MjY6MzciKCpxd2Zkb2ZmWHRhcHVaam1qZXElOiY4MTU5MjYoLyVwdmdnbGVnWX9wYl9maWJubnBpf21jX21lYGJsIDxsYmtzYSQjdXttYGNvYl9tZWBibF1zeG8lOiZgdXF5OCklc2VzKnx2bGRlKGlsai90em5jYG5jVWpqYWNtcio9OzYzNjI5Njw3PDo7Pz82NTArfVg8OUlCYjNYbmt6bGRlLGx6ZmAiKCpxd2Zkb2ZmWGlpaWZgVnd0ZlxvdHB4ciczIG5+d3dzPicudWtxKH50bm1jJmJqZC12eGxhaWhtXmxkY2FvcCg0PTg4MDw7ND41PjM9MTQwOzIpf1o+ME9MaTVWbGl4bmZsKmJxYG4gKihzdW9iYW1gVmBnZG1iclt9c2krOCRid3NwdzIuKnlgdSR3cGlpby9mZm8penFoZm1kZFprY2hkZnVzKz8yMjs1Nzk0KDE3MDc3PzM/PzElLCZsZGNod2p+XHdya25oaWwgPGxia3NhJCNhbGRnf29zX3R6bmNgbmNVamphY20jP29janlmKyJiZ21pZnVvZGQlOmp9bWklIGBlb2tvc1dzYHh3Y3l3WHNhZnUnM2xzZm8rImpndWxva2Vrd25vansjP2d3amZ+KyJjbW4nM2xzZm8rImdnbndta2hrd2JzJjJvcGVuKihza2FnbSM/ciBvbiE9IjdsZzFvNjQ9YTJhMjhnYGggKih2dWwmMiNtfXZ2eTkoL2V4aCt9dW9+d2JyKmtuaCYzKDssYGVrJ2hhJjFibDdhNDY/YzBoNDZsZmYubntuaysuJHpvZmNhV3V8eWckMCFkaXBxIykrbGdnZiU6JltgaylDaH5saWlrKi0nb3dqZlxpYWltIz8rUWdkI0ZucGdvbGYuJl5bJSwma25wZ3Z0c1xkb2BtIz8rV1UoLyVja31vcXt7JDAhUm5tfGRhKVFya3dicyYkI2dmd2huamlnW2pufSs4fSh3fnBhKjsnWW1qc2RobiYkI2ZmbXRuamlhcG1yJzNZXVEuPjgqPzY9PDc/JjE+LjU8MDw8NFsmWCo5PCY2MjE3MzMvNTkqPjg2OTYwVy9cLT0wLzY5MDE+NysyPSY3PDoyMjxeK1spMTkrOjI0PTczLDYxLzQ9Mz8/NVpdWXUtJ2h2cnhqZXVwbXInM3l7dy8lY2tmdXdgYHN+bHVzJjJvcGVuKihxYnRzbWRxVmFpf21zIj44LSdvY3BlcW50YVdianxscig5NywmbW9xYHZvb3AlOn8qaWR6anJrZHQiPlNcKSt2dG9tY3MmMlpYJSBzeG90Ij5TXCkrd3VvcVhtYWZ1bGZsdSg5XF0oKnJ8ZGBpZnAlOl9VfCkrZGd8bHVpcG1lJzNkZ2ZwYiwmemRxfmdjfmZjIj5uYGl6Zyooc2hzd2FjaXBddW9tdGlwYXdgKzhga290ZSgqZ2xldmN4XGtlcm1tJzMgamV0JSwmZGBrbiA8KGZpIigqdWxkZ3V+YmpwW2VyJzMgNz4wNjY1PDMyPjo0PCF6");
//	}
	
}
