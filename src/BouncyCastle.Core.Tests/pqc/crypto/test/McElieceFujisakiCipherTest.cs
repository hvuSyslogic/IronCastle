namespace org.bouncycastle.pqc.crypto.test
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using McElieceCCA2KeyGenerationParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
	using McElieceCCA2KeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
	using McElieceCCA2Parameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
	using McElieceFujisakiCipher = org.bouncycastle.pqc.crypto.mceliece.McElieceFujisakiCipher;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class McElieceFujisakiCipherTest : SimpleTest
	{

		internal SecureRandom keyRandom = new SecureRandom();

		public override string getName()
		{
			return "McElieceFujisaki";

		}


		public override void performTest()
		{
			int numPassesKPG = 1;
			int numPassesEncDec = 10;
			Random rand = new Random();
			byte[] mBytes;
			for (int j = 0; j < numPassesKPG; j++)
			{
				McElieceCCA2Parameters @params = new McElieceCCA2Parameters();
				McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
				McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, @params);

				mcElieceCCA2KeyGen.init(genParam);
				AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();

				ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
				Digest msgDigest = new SHA256Digest();
				McElieceFujisakiCipher mcElieceFujisakiDigestCipher = new McElieceFujisakiCipher();


				for (int k = 1; k <= numPassesEncDec; k++)
				{
					JavaSystem.@out.println("############### test: " + k);
					// initialize for encryption
					mcElieceFujisakiDigestCipher.init(true, param);

					// generate random message
					int mLength = (rand.nextInt() & 0x1f) + 1;
					mBytes = new byte[mLength];
					rand.nextBytes(mBytes);

					msgDigest.update(mBytes, 0, mBytes.Length);
					byte[] hash = new byte[msgDigest.getDigestSize()];
					msgDigest.doFinal(hash, 0);

					// encrypt
					byte[] enc = mcElieceFujisakiDigestCipher.messageEncrypt(hash);

					// initialize for decryption
					mcElieceFujisakiDigestCipher.init(false, pair.getPrivate());
					byte[] constructedmessage = mcElieceFujisakiDigestCipher.messageDecrypt(enc);

					// XXX write in McElieceFujisakiDigestCipher?


					bool verified = true;
					for (int i = 0; i < hash.Length; i++)
					{
						verified = verified && hash[i] == constructedmessage[i];
					}

					if (!verified)
					{
						fail("en/decryption fails");
					}
					else
					{
						JavaSystem.@out.println("test okay");
						JavaSystem.@out.println();
					}

				}
			}

		}

		public static void Main(string[] args)
		{
			runTest(new McElieceFujisakiCipherTest());
		}

	}

}