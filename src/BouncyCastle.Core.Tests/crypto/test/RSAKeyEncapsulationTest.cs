namespace org.bouncycastle.crypto.test
{

	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using RSAKeyPairGenerator = org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
	using RSAKeyEncapsulation = org.bouncycastle.crypto.kems.RSAKeyEncapsulation;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using RSAKeyGenerationParameters = org.bouncycastle.crypto.@params.RSAKeyGenerationParameters;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Tests for the RSA Key Encapsulation Mechanism
	/// </summary>
	public class RSAKeyEncapsulationTest : SimpleTest
	{
		public override string getName()
		{
			return "RSAKeyEncapsulation";
		}

		public override void performTest()
		{
			// Generate RSA key pair
			RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
			rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 1024, 5));
			AsymmetricCipherKeyPair keys = rsaGen.generateKeyPair();

			// Set RSA-KEM parameters
			RSAKeyEncapsulation kem;
			KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA1Digest());
			SecureRandom rnd = new SecureRandom();
			byte[] @out = new byte[128];
			KeyParameter key1, key2;

			// Test RSA-KEM
			kem = new RSAKeyEncapsulation(kdf, rnd);

			kem.init(keys.getPublic());
			key1 = (KeyParameter)kem.encrypt(@out, 128);

			kem.init(keys.getPrivate());
			key2 = (KeyParameter)kem.decrypt(@out, 128);

			if (!areEqual(key1.getKey(), key2.getKey()))
			{
				fail("failed test");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new RSAKeyEncapsulationTest());
		}
	}

}