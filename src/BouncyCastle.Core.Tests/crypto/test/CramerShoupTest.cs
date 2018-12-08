using System;

namespace org.bouncycastle.crypto.test
{

	using DHStandardGroups = org.bouncycastle.crypto.agreement.DHStandardGroups;
	using CramerShoupCiphertext = org.bouncycastle.crypto.engines.CramerShoupCiphertext;
	using CramerShoupCoreEngine = org.bouncycastle.crypto.engines.CramerShoupCoreEngine;
	using CramerShoupCiphertextException = org.bouncycastle.crypto.engines.CramerShoupCoreEngine.CramerShoupCiphertextException;
	using CramerShoupKeyPairGenerator = org.bouncycastle.crypto.generators.CramerShoupKeyPairGenerator;
	using CramerShoupParametersGenerator = org.bouncycastle.crypto.generators.CramerShoupParametersGenerator;
	using CramerShoupKeyGenerationParameters = org.bouncycastle.crypto.@params.CramerShoupKeyGenerationParameters;
	using CramerShoupParameters = org.bouncycastle.crypto.@params.CramerShoupParameters;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CramerShoupTest : SimpleTest
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private static readonly SecureRandom RND = new SecureRandom();

		private AsymmetricCipherKeyPair keyPair;

		public static void Main(string[] args)
		{
			runTest(new CramerShoupTest());
		}

		public override string getName()
		{
			return "CramerShoup";
		}


		public override void performTest()
		{
			BigInteger pSubOne = DHStandardGroups.rfc3526_2048.getP().subtract(ONE);
			for (int i = 0; i < 10; ++i)
			{
				BigInteger message = BigIntegers.createRandomInRange(ONE, pSubOne, RND);

				BigInteger m1 = encDecTest(message);
				BigInteger m2 = labelledEncDecTest(message, "myRandomLabel");
				BigInteger m3 = encDecEncodingTest(message);
				BigInteger m4 = labelledEncDecEncodingTest(message, "myOtherCoolLabel");

				if (!message.Equals(m1) || !message.Equals(m2) || !message.Equals(m3) || !message.Equals(m4))
				{
					fail("decrypted message != original message");
				}
			}
		}

		private BigInteger encDecEncodingTest(BigInteger m)
		{
			CramerShoupCiphertext ciphertext = encrypt(m);
			byte[] c = ciphertext.toByteArray();
			CramerShoupCiphertext decC = new CramerShoupCiphertext(c);
			return decrypt(decC);
		}

		private BigInteger labelledEncDecEncodingTest(BigInteger m, string l)
		{
			byte[] c = encrypt(m, l).toByteArray();
			return decrypt(new CramerShoupCiphertext(c), l);
		}

		private BigInteger encDecTest(BigInteger m)
		{
			CramerShoupCiphertext c = encrypt(m);
			return decrypt(c);
		}

		private BigInteger labelledEncDecTest(BigInteger m, string l)
		{
			CramerShoupCiphertext c = encrypt(m, l);
			return decrypt(c, l);
		}


		private BigInteger decrypt(CramerShoupCiphertext ciphertext)
		{
			return decrypt(ciphertext, null);
		}

		private BigInteger decrypt(CramerShoupCiphertext ciphertext, string label)
		{

			CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
			if (!string.ReferenceEquals(label, null))
			{
				engine.init(false, keyPair.getPrivate(), label);
			}
			else
			{
				engine.init(false, keyPair.getPrivate());
			}
			try
			{
				BigInteger m = engine.decryptBlock(ciphertext);

				return m;
			}
			catch (CramerShoupCoreEngine.CramerShoupCiphertextException e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}

			return null;
		}

		private CramerShoupCiphertext encrypt(BigInteger message)
		{
			return encrypt(message, null);
		}

		private CramerShoupCiphertext encrypt(BigInteger message, string label)
		{
			CramerShoupKeyPairGenerator kpGen = new CramerShoupKeyPairGenerator();
			CramerShoupParametersGenerator pGen = new CramerShoupParametersGenerator();

			pGen.init(2048, 1, RND);
			CramerShoupParameters @params = pGen.generateParameters(DHStandardGroups.rfc3526_2048);
			CramerShoupKeyGenerationParameters param = new CramerShoupKeyGenerationParameters(RND, @params);

			kpGen.init(param);
			keyPair = kpGen.generateKeyPair();

			CramerShoupCoreEngine engine = new CramerShoupCoreEngine();
			if (!string.ReferenceEquals(label, null))
			{
				engine.init(true, keyPair.getPublic(), label);
			}
			else
			{
				engine.init(true, keyPair.getPublic());
			}

			CramerShoupCiphertext ciphertext = engine.encryptBlock(message);

			return ciphertext;
		}
	}

}