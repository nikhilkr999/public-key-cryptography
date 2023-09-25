package diffieHellmanKeyExchange;

import java.math.BigInteger;
import java.util.Random;

public class DiffieHellman{
	
	public static void main(String[] args) {
		BigInteger n = new BigInteger(Integer.toString(37));
		
		//g is a primitive root of n
		BigInteger g = new BigInteger(Integer.toString(13));
		
		Test algorithm = new Test();
		algorithm.generatePrivateKeys(n, g);
	}
}


 class Test {
	
	private Random random = new Random();
	
	
	
	public void generatePrivateKeys(BigInteger n, BigInteger g) {
		//random number for alice x < n-1
		int rand1 = random.nextInt(n.intValue()-2)+1;
		BigInteger x = new BigInteger(Integer.toString(rand1));
		
		//random number for Bob y < n-1
		int rand2 = random.nextInt(n.intValue()-2)+1;
		BigInteger y = new BigInteger(Integer.toString(rand2));
		
		//calculate g^x mod n which is Alice Key K1
		BigInteger k1 = g.modPow(x, n);
		
		//calculate g^y mod n which is Bob Key K2
		BigInteger k2 = g.modPow(y, n);
		
		
		//they can calculate the same Private Key
		//Alice Private key
		BigInteger key1 = k2.modPow(x, n);
		
		//Bob Private key
		BigInteger key2 = k1.modPow(y, n);
		
		//it is difficult for an attacker to get x and y , it is descrete log problem
		System.out.println("Alice Private key :" + key1.intValue());
		System.out.println("Bob Private key :" + key2.intValue());
	}	

}
