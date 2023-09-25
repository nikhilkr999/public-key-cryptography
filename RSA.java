package RSA;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	//parameter 'e' for encryption
	private BigInteger publicKey;
	//parameter 'd'  (decryption)
	private BigInteger privateKey;
	//n=p*q
	private BigInteger n;
	//random number
	private SecureRandom random;
	
	public RSA() {
		this.random = new SecureRandom();
	}
	
	public void generateKey(int keyDigits) {
		//p  is a large prime number
		BigInteger p = BigInteger.probablePrime(keyDigits, random);
		
		//q is a large prime number
		BigInteger q = BigInteger.probablePrime(keyDigits, random);
		
		//n=p*q
		//this is a trapdoor function
		 n = p.multiply(q);
		 
		//Euler's totient phi function phi = (p-1)*(q-1)
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		//have to use GCD to fine e and GCD(e, phi)=1
		//so e is coprime to phi
		BigInteger e = generatePublicFactor(phi);
		
		//modular inverse of e - mod phi (extended euclidean algorithm)
		BigInteger d = e.modInverse(phi);
		
		//this is how we can decrypt message
		this.privateKey=d;
		
		//for decrypt
		this.publicKey=e;
		
	}
	
	
	
	private BigInteger generatePublicFactor(BigInteger phi) {
		
		BigInteger e = new BigInteger(phi.bitLength(), random);
		
		//we are after a coprime where gcd(e, phi)=1
		while(!e.gcd(phi).equals(BigInteger.ONE));
			e = new BigInteger(phi.bitLength(), random);
			
		return e;
	}

	public BigInteger encryption(String message) {
		return encrypt(publicKey, n, message);
	}
	public String decrypt(BigInteger cipher) {
		return decrypt(privateKey, n, cipher);
	}
	
	
	private BigInteger encrypt(BigInteger e, BigInteger n, String message) {
		byte[] messageByte = message.getBytes();
		BigInteger messageInt = new BigInteger(messageByte);
		
		//use modular exponentiation
		//cipherText = message^e mod n
		
		return messageInt.modPow(e, n);
	}
	

	private String decrypt(BigInteger d, BigInteger n, BigInteger cipherText) {
		//will use modular exponentiation for decryption also
		//message = cipherText^d mod n
		
		BigInteger message = cipherText.modPow(d, n);
		
		return new String(message.toByteArray());
	}
	
	public static void main(String[] args) {
		String message = "Hi";
		RSA rsa = new RSA();
		rsa.generateKey(1024);
		
		System.out.println("Plain Text : "+message);
		
		BigInteger cipherText = rsa.encryption(message);
		//String s = new String(cipherText.toByteArray());
		System.out.println("Encrypted Text: "+ cipherText);
		
		String msg = rsa.decrypt(cipherText);
		System.out.println("Decrypted cipher : "+msg);
	}
}
