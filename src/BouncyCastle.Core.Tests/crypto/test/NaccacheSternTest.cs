namespace org.bouncycastle.crypto.test
{

	using NaccacheSternEngine = org.bouncycastle.crypto.engines.NaccacheSternEngine;
	using NaccacheSternKeyPairGenerator = org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
	using NaccacheSternKeyGenerationParameters = org.bouncycastle.crypto.@params.NaccacheSternKeyGenerationParameters;
	using NaccacheSternKeyParameters = org.bouncycastle.crypto.@params.NaccacheSternKeyParameters;
	using NaccacheSternPrivateKeyParameters = org.bouncycastle.crypto.@params.NaccacheSternPrivateKeyParameters;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Test case for NaccacheStern cipher. For details on this cipher, please see
	/// 
	/// http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	/// 
	/// Performs the following tests: 
	///  <ul>
	///  <li> Toy example from the NaccacheSternPaper </li>
	///  <li> 768 bit test with text "Now is the time for all good men." (ripped from RSA test) and
	///     the same test with the first byte replaced by 0xFF </li>
	///  <li> 1024 bit test analog to 768 bit test </li>
	///  </ul>
	/// </summary>
	public class NaccacheSternTest : SimpleTest
	{
		internal const bool debug = false;

		internal static readonly NaccacheSternEngine cryptEng = new NaccacheSternEngine();

		internal static readonly NaccacheSternEngine decryptEng = new NaccacheSternEngine();

		// Values from NaccacheStern paper
		internal static readonly BigInteger a = BigInteger.valueOf(101);

		internal static readonly BigInteger u1 = BigInteger.valueOf(3);

		internal static readonly BigInteger u2 = BigInteger.valueOf(5);

		internal static readonly BigInteger u3 = BigInteger.valueOf(7);

		internal static readonly BigInteger b = BigInteger.valueOf(191);

		internal static readonly BigInteger v1 = BigInteger.valueOf(11);

		internal static readonly BigInteger v2 = BigInteger.valueOf(13);

		internal static readonly BigInteger v3 = BigInteger.valueOf(17);

		internal static readonly BigInteger ONE = BigInteger.valueOf(1);

		internal static readonly BigInteger TWO = BigInteger.valueOf(2);

		internal static readonly BigInteger sigma = u1.multiply(u2).multiply(u3).multiply(v1).multiply(v2).multiply(v3);

		internal static readonly BigInteger p = TWO.multiply(a).multiply(u1).multiply(u2).multiply(u3).add(ONE);

		internal static readonly BigInteger q = TWO.multiply(b).multiply(v1).multiply(v2).multiply(v3).add(ONE);

		internal static readonly BigInteger n = p.multiply(q);

		internal static readonly BigInteger phi_n = p.subtract(ONE).multiply(q.subtract(ONE));

		internal static readonly BigInteger g = BigInteger.valueOf(131);

		internal static readonly Vector smallPrimes = new Vector();

		// static final BigInteger paperTest = BigInteger.valueOf(202);

		internal const string input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

		internal static readonly BigInteger paperTest = BigInteger.valueOf(202);

		//
		// to check that we handling byte extension by big number correctly.
		//
		internal const string edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

		static NaccacheSternTest()
		{
			cryptEng.setDebug(debug);
			decryptEng.setDebug(debug);

			// First the Parameters from the NaccacheStern Paper
			// (see http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf )

			smallPrimes.addElement(u1);
			smallPrimes.addElement(u2);
			smallPrimes.addElement(u3);
			smallPrimes.addElement(v1);
			smallPrimes.addElement(v2);
			smallPrimes.addElement(v3);
		}

		public override string getName()
		{
			return "NaccacheStern";
		}

		public override void performTest()
		{
			// Test with given key from NaccacheSternPaper (totally insecure)

			NaccacheSternKeyParameters pubParameters = new NaccacheSternKeyParameters(false, g, n, sigma.bitLength());

			NaccacheSternPrivateKeyParameters privParameters = new NaccacheSternPrivateKeyParameters(g, n, sigma.bitLength(), smallPrimes, phi_n);

			AsymmetricCipherKeyPair pair = new AsymmetricCipherKeyPair(pubParameters, privParameters);

			// Initialize Engines with KeyPair

			if (debug)
			{
				JavaSystem.@out.println("initializing encryption engine");
			}
			cryptEng.init(true, pair.getPublic());

			if (debug)
			{
				JavaSystem.@out.println("initializing decryption engine");
			}
			decryptEng.init(false, pair.getPrivate());

			byte[] data = paperTest.toByteArray();

			if (!(new BigInteger(data)).Equals(new BigInteger(enDeCrypt(data))))
			{
				fail("failed NaccacheStern paper test");
			}

			//
			// key generation test
			//

			// 
			// 768 Bit test
			//

			if (debug)
			{
				JavaSystem.@out.println();
				JavaSystem.@out.println("768 Bit TEST");
			}

			// specify key generation parameters
			NaccacheSternKeyGenerationParameters genParam = new NaccacheSternKeyGenerationParameters(new SecureRandom(), 768, 8, 30, debug);

			// Initialize Key generator and generate key pair
			NaccacheSternKeyPairGenerator pGen = new NaccacheSternKeyPairGenerator();
			pGen.init(genParam);

			pair = pGen.generateKeyPair();

			if (((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() < 768)
			{
				JavaSystem.@out.println("FAILED: key size is <786 bit, exactly " + ((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() + " bit");
				fail("failed key generation (768) length test");
			}

			// Initialize Engines with KeyPair

			if (debug)
			{
				JavaSystem.@out.println("initializing " + genParam.getStrength() + " bit encryption engine");
			}
			cryptEng.init(true, pair.getPublic());

			if (debug)
			{
				JavaSystem.@out.println("initializing " + genParam.getStrength() + " bit decryption engine");
			}
			decryptEng.init(false, pair.getPrivate());

			// Basic data input
			data = Hex.decode(input);

			if (!(new BigInteger(1, data)).Equals(new BigInteger(1, enDeCrypt(data))))
			{
				fail("failed encryption decryption (" + genParam.getStrength() + ") basic test");
			}

			// Data starting with FF byte (would be interpreted as negative
			// BigInteger)

			data = Hex.decode(edgeInput);

			if (!(new BigInteger(1, data)).Equals(new BigInteger(1, enDeCrypt(data))))
			{
				fail("failed encryption decryption (" + genParam.getStrength() + ") edgeInput test");
			}

			// 
			// 1024 Bit Test
			// 
	/*
	        if (debug)
	        {
	            JavaSystem.@out.println();
	            JavaSystem.@out.println("1024 Bit TEST");
	        }
	
	        // specify key generation parameters
	        genParam = new NaccacheSternKeyGenerationParameters(new SecureRandom(), 1024, 8, 40);
	
	        pGen.init(genParam);
	        pair = pGen.generateKeyPair();
	
	        if (((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() < 1024)
	        {
	            if (debug)
	            {
	                JavaSystem.@out.println("FAILED: key size is <1024 bit, exactly "
	                                + ((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() + " bit");
	            }
	            fail("failed key generation (1024) length test");
	        }
	
	        // Initialize Engines with KeyPair
	
	        if (debug)
	        {
	            JavaSystem.@out.println("initializing " + genParam.getStrength() + " bit encryption engine");
	        }
	        cryptEng.init(true, pair.getPublic());
	
	        if (debug)
	        {
	            JavaSystem.@out.println("initializing " + genParam.getStrength() + " bit decryption engine");
	        }
	        decryptEng.init(false, pair.getPrivate());
	
	        if (debug)
	        {
	            JavaSystem.@out.println("Data is           " + new BigInteger(1, data));
	        }
	
	        // Basic data input
	        data = Hex.decode(input);
	
	        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
	        {
	            fail("failed encryption decryption (" + genParam.getStrength() + ") basic test");
	        }
	
	        // Data starting with FF byte (would be interpreted as negative
	        // BigInteger)
	
	        data = Hex.decode(edgeInput);
	
	        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
	        {
	            fail("failed encryption decryption (" + genParam.getStrength() + ") edgeInput test");
	        }
	*/
			// END OF TEST CASE

			try
			{
				(new NaccacheSternEngine()).processBlock(new byte[]{1}, 0, 1);
				fail("failed initialisation check");
			}
			catch (IllegalStateException)
			{
				// expected
			}
			catch (InvalidCipherTextException)
			{
				fail("failed initialisation check");
			}

			if (debug)
			{
				JavaSystem.@out.println("All tests successful");
			}
		}

		private byte[] enDeCrypt(byte[] input)
		{

			// create work array
			byte[] data = new byte[input.Length];
			JavaSystem.arraycopy(input, 0, data, 0, data.Length);

			// Perform encryption like in the paper from Naccache-Stern
			if (debug)
			{
				JavaSystem.@out.println("encrypting data. Data representation\n" + "As BigInteger: " + new BigInteger(1, data));
				JavaSystem.@out.println("data length is " + data.Length);
			}

			try
			{
				data = cryptEng.processData(data);
			}
			catch (InvalidCipherTextException e)
			{
				if (debug)
				{
					JavaSystem.@out.println("failed - exception " + e.ToString() + "\n" + e.Message);
				}
				fail("failed - exception " + e.ToString() + "\n" + e.Message);
			}

			if (debug)
			{
				JavaSystem.@out.println("enrypted data representation\n" + "As BigInteger: " + new BigInteger(1, data));
				JavaSystem.@out.println("data length is " + data.Length);
			}

			try
			{
				data = decryptEng.processData(data);
			}
			catch (InvalidCipherTextException e)
			{
				if (debug)
				{
					JavaSystem.@out.println("failed - exception " + e.ToString() + "\n" + e.Message);
				}
				fail("failed - exception " + e.ToString() + "\n" + e.Message);
			}

			if (debug)
			{
				JavaSystem.@out.println("decrypted data representation\n" + "As BigInteger: " + new BigInteger(1, data));
				JavaSystem.@out.println("data length is " + data.Length);
			}

			return data;

		}

		public static void Main(string[] args)
		{
			runTest(new NaccacheSternTest());
		}
	}

}