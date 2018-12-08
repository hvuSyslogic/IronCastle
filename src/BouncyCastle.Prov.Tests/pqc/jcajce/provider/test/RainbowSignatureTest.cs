using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using TestCase = junit.framework.TestCase;
	using RainbowParameterSpec = org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Test cases for the use of Rainbow with the BCPQC provider.
	/// </summary>
	public class RainbowSignatureTest : TestCase
	{

		protected internal KeyPairGenerator kpg;

		protected internal Signature sig;

		private Signature sigVerify;

		private KeyPair keyPair;

		private PublicKey pubKey;

		private PrivateKey privKey;

		private byte[] mBytes;

		private byte[] sigBytes;

		private bool valid;

		internal Random rand = new Random();

		private KeyFactory kf;


		public virtual void setUp()
		{
			if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
			{
				Security.addProvider(new BouncyCastlePQCProvider());
			}
		}

		/// <summary>
		/// Test signature generation and verification
		/// </summary>
		/// <param name="numPassesKPG">    the number of key pair generation passes </param>
		/// <param name="numPassesSigVer"> the number of sign/verify passes </param>
		/// <param name="kpgParams">       the parameters for the key pair generator </param>
		public void performSignVerifyTest(int numPassesKPG, int numPassesSigVer, AlgorithmParameterSpec kpgParams)
		{
			this.performSignVerifyTest(numPassesKPG, numPassesSigVer, kpgParams, 100);
		}

		/// <summary>
		/// Test signature generation and verification
		/// </summary>
		/// <param name="numPassesKPG">    the number of key pair generation passes </param>
		/// <param name="numPassesSigVer"> the number of sign/verify passes </param>
		/// <param name="kpgParams">       the parameters for the key pair generator </param>
		/// <param name="messageSize">     length of the messages which are signed in bytes </param>
		public void performSignVerifyTest(int numPassesKPG, int numPassesSigVer, AlgorithmParameterSpec kpgParams, int messageSize)
		{
			// generate new signature instance for verification
			//            sigVerify = (Signature) sig.getClass().newInstance();
			sigVerify = Signature.getInstance("SHA384withRainbow", "BCPQC");

			for (int j = 0; j < numPassesKPG; j++)
			{
				// generate key pair
				if (kpgParams != null)
				{
					kpg.initialize(kpgParams);
				}
				keyPair = kpg.genKeyPair();
				pubKey = keyPair.getPublic();
				privKey = keyPair.getPrivate();

				// initialize signature instances
				sig.initSign(privKey);
				sigVerify.initVerify(pubKey);

				for (int k = 1; k <= numPassesSigVer; k++)
				{
					// generate random message
					mBytes = new byte[messageSize];
					rand.nextBytes(mBytes);

					// sign
					sig.update(mBytes);
					sigBytes = sig.sign();

					// verify
					sigVerify.update(mBytes);
					valid = sigVerify.verify(sigBytes);

					// compare
					assertTrue("Signature generation and verification test failed.\n" + @"Message: """ + StringHelper.NewString(Hex.encode(mBytes)) + @"""\n" + privKey + "\n" + pubKey, valid);
				}
			}
		}

		/// <summary>
		/// Test signature generation and verification
		/// </summary>
		/// <param name="numPassesKPG">    the number of key pair generation passes </param>
		/// <param name="numPassesSigVer"> the number of sign/verify passes </param>
		/// <param name="keySize">         the key size for the key pair generator </param>
		public void performSignVerifyTest(int numPassesKPG, int numPassesSigVer, int keySize)
		{
			for (int j = 0; j < numPassesKPG; j++)
			{
				// generate key pair

				kpg.initialize(keySize);
				keyPair = kpg.genKeyPair();
				pubKey = keyPair.getPublic();
				//writeKey("RainbowPubKey", pubKey);
				privKey = keyPair.getPrivate();
				// it causes errors! cause RainbowParameters will be null
				//pubKey = getPublicKey("RainbowPubKey");

				// initialize signature instances
				sig.initSign(privKey, new SecureRandom());
				sigVerify.initVerify(pubKey);

				for (int k = 1; k <= numPassesSigVer; k++)
				{
					// generate random message
					const int messageSize = 100;
					mBytes = new byte[messageSize];
					rand.nextBytes(mBytes);

					sig.update(mBytes, 0, mBytes.Length);
					sigBytes = sig.sign();

					// verify
					sigVerify.update(mBytes, 0, mBytes.Length);
					valid = sigVerify.verify(sigBytes);

					// compare
					assertTrue("Signature generation and verification test failed.\n" + @"Message: """ + StringHelper.NewString(Hex.encode(mBytes)) + @"""\n" + privKey + "\n" + pubKey, valid);
				}
			}

		}

		/// <summary>
		/// Using ParameterSpecs to initialize the key pair generator without initialization.
		/// </summary>

		public virtual void testRainbowWithSHA224()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
			sig = Signature.getInstance("SHA224WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
			sigVerify = Signature.getInstance("SHA224WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
			performSignVerifyTest(1, 1, 28);
		}

		public virtual void testRainbowithSHA256()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");
			sig = Signature.getInstance("SHA256WITHRainbow");
			sigVerify = Signature.getInstance("SHA256WITHRainbow");
			performSignVerifyTest(1, 1, 32);
		}

		public virtual void testRainbowWithSHA384()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");
			sig = Signature.getInstance("SHA384WITHRainbow");
			sigVerify = Signature.getInstance("SHA384WITHRainbow");
			performSignVerifyTest(1, 1, 48);
		}

		public virtual void testRainbowWithSHA512()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");
			sig = Signature.getInstance("SHA512WITHRainbow");
			sigVerify = Signature.getInstance("SHA512WITHRainbow");
			performSignVerifyTest(1, 1, 64);
		}

		public virtual void test_KeyFactory()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");

			KeyFactory kf = KeyFactory.getInstance("Rainbow");

			AlgorithmParameterSpec specs = new RainbowParameterSpec();
			try
			{
				kpg.initialize(specs);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}
			// XXX
			kpg.initialize(5);
			keyPair = kpg.genKeyPair();
			pubKey = keyPair.getPublic();
			privKey = keyPair.getPrivate();

			byte[] pubKeyBytes = pubKey.getEncoded();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKey.getEncoded());

			PublicKey publicKeyKF = kf.generatePublic(pubKeySpec);

			assertEquals(pubKey, publicKeyKF);
			assertEquals(pubKey.GetHashCode(), publicKeyKF.GetHashCode());

			PrivateKey privKeyKF = kf.generatePrivate(privKeySpec);

			assertEquals(privKey, privKeyKF);
			assertEquals(privKey.GetHashCode(), privKeyKF.GetHashCode());
		}

		public virtual void testSignVerifyWithRandomParams()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");
			sig = Signature.getInstance("SHA384WITHRainbow");
			int[] vi;

			for (int kgen = 1; kgen <= 10; kgen++)
			{
				vi = chooseRandomParams();
				RainbowParameterSpec rbParams = new RainbowParameterSpec(vi);
				performSignVerifyTest(1, 100, rbParams);
			}
		}


		/// <summary>
		/// build up the set of vinegars per layer (vi)
		/// </summary>
		/// <returns> parameters vi </returns>
		private int[] chooseRandomParams()
		{
			int n = rand.nextInt(10) + 2;
			int[] vi = new int[n];

			vi[0] = rand.nextInt(10) + 2;
			for (int i = 1; i < n; i++)
			{
				vi[i] = vi[i - 1];
				vi[i] += rand.nextInt(10) + 1;
			}
			return vi;
		}

		/*
		 public void testSignVerifyWithSpecialParams() throws Exception {
		     kpg = KeyPairGenerator.getInstance("RainbowWithSHA384");
		     sig = Signature.getInstance("SHA384WITHRainbow");
		     int[] vi = { 3, 20, 25, 30, 40, 60, 80, 100 };
		     performSignVerifyTest(10, 200, new RainbowParameterSpec(vi));
		 }
		 */

		public virtual void testSignVerifyWithDefaultParams()
		{
			kpg = KeyPairGenerator.getInstance("Rainbow");
			sig = Signature.getInstance("SHA384WITHRainbow");
			performSignVerifyTest(15, 100, new RainbowParameterSpec());
		}

		public virtual PublicKey getPublicKey(string file)
		{
			kf = KeyFactory.getInstance("Rainbow");
			byte[] pubKeyBytes = getBytesFromFile(new File(file));
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
			return kf.generatePublic(pubKeySpec);
		}


		public virtual byte[] getBytesFromFile(File file)
		{
			InputStream @is = new FileInputStream(file);

			// Get the size of the file
			long length = file.length();

			// You cannot create an array using a long type.
			// It needs to be an int type.
			// Before converting to an int type, check
			// to ensure that file is not larger than Integer.MAX_VALUE.
			if (length > int.MaxValue)
			{
				// File is too large
			}

			// Create the byte array to hold the data
			byte[] bytes = new byte[(int)length];

			// Read in the bytes
			int offset = 0;
			int numRead = 0;
			while (offset < bytes.Length && (numRead = @is.read(bytes, offset, bytes.Length - offset)) >= 0)
			{
				offset += numRead;
			}

			// Ensure all the bytes have been read in
			if (offset < bytes.Length)
			{
				throw new IOException("Could not completely read file " + file.getName());
			}

			// Close the input stream and return bytes
			@is.close();
			return bytes;
		}

	}


}