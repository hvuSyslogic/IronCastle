namespace org.bouncycastle.pqc.crypto.test
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using McElieceCipher = org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
	using McElieceKeyGenerationParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
	using McElieceKeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
	using McElieceParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class McElieceCipherTest : SimpleTest
	{

		internal SecureRandom keyRandom = new SecureRandom();

		public override string getName()
		{
			return "McEliecePKCS";

		}


		public override void performTest()
		{
			int numPassesKPG = 1;
			int numPassesEncDec = 10;
			Random rand = new Random();
			byte[] mBytes;
			for (int j = 0; j < numPassesKPG; j++)
			{

				McElieceParameters @params = new McElieceParameters();
				McElieceKeyPairGenerator mcElieceKeyGen = new McElieceKeyPairGenerator();
				McElieceKeyGenerationParameters genParam = new McElieceKeyGenerationParameters(keyRandom, @params);

				mcElieceKeyGen.init(genParam);
				AsymmetricCipherKeyPair pair = mcElieceKeyGen.generateKeyPair();

				ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
				Digest msgDigest = new SHA256Digest();
				McElieceCipher mcEliecePKCSDigestCipher = new McElieceCipher();


				for (int k = 1; k <= numPassesEncDec; k++)
				{
					JavaSystem.@out.println("############### test: " + k);
					// initialize for encryption
					mcEliecePKCSDigestCipher.init(true, param);

					// generate random message
					int mLength = (rand.nextInt() & 0x1f) + 1;
					mBytes = new byte[mLength];
					rand.nextBytes(mBytes);

					// encrypt
					msgDigest.update(mBytes, 0, mBytes.Length);
					byte[] hash = new byte[msgDigest.getDigestSize()];

					msgDigest.doFinal(hash, 0);

					byte[] enc = mcEliecePKCSDigestCipher.messageEncrypt(hash);

					// initialize for decryption
					mcEliecePKCSDigestCipher.init(false, pair.getPrivate());
					byte[] constructedmessage = mcEliecePKCSDigestCipher.messageDecrypt(enc);

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
			runTest(new McElieceCipherTest());
		}

	}

}