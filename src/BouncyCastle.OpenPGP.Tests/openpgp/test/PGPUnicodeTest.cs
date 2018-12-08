using System;

namespace org.bouncycastle.openpgp.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using PBESecretKeyDecryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyDecryptor;
	using PGPDigestCalculatorProvider = org.bouncycastle.openpgp.@operator.PGPDigestCalculatorProvider;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcaPGPDigestCalculatorProviderBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;

	public class PGPUnicodeTest : TestCase
	{
		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}

		public virtual void test_key(BigInteger keyId, string passphrase)
		{

			PGPSecretKeyRingCollection secretKeyRing = loadSecretKeyCollection("secring.gpg");

			PGPSecretKeyRing secretKey = secretKeyRing.getSecretKeyRing(keyId.longValue());
			assertNotNull("Could not locate secret keyring with Id=" + keyId.ToString(16), secretKey);

			PGPSecretKey key = secretKey.getSecretKey();
			assertNotNull("Could not locate secret key!", key);

			try
			{
				PGPDigestCalculatorProvider calcProvider = (new JcaPGPDigestCalculatorProviderBuilder()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

				PBESecretKeyDecryptor decryptor = (new JcePBESecretKeyDecryptorBuilder(calcProvider)).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase.ToCharArray());

				PGPPrivateKey privateKey = key.extractPrivateKey(decryptor);

				assertTrue(privateKey.getKeyID() == keyId.longValue());

			}
			catch (PGPException e)
			{
				throw new PGPException("Password incorrect!", e);
			}

			// all fine!
		}

		public virtual void test_UmlautPassphrase()
		{

			try
			{
				BigInteger keyId = new BigInteger("362961283C48132B9F14C5C3EC87272EFCB986D2", 16);

				string passphrase = new string("Händle".GetBytes("UTF-16"), "UTF-16");
	//            FileInputStream passwordFile = new FileInputStream("testdata/passphrase_for_test.txt");
	//            byte[] password = new byte[passwordFile.available()];
	//            passwordFile.read(password);
	//            passwordFile.close();
	//            String passphrase = new String(password);            

				test_key(keyId, passphrase);

				// all fine!

			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
				fail(e.Message);
			}
		}

		public virtual void test_ASCIIPassphrase()
		{

			try
			{
				BigInteger keyId = new BigInteger("A392B7310C64026022405257AA2AAAC7CB417459", 16);

				string passphrase = "Admin123";

				test_key(keyId, passphrase);

				// all fine!

			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
				fail(e.Message);
			}
		}

		public virtual void test_CyrillicPassphrase()
		{

			try
			{
				BigInteger keyId = new BigInteger("B7773AF32BE4EC1806B1BACC4680E7F3960C44E7", 16);

				// XXX The password text file must not have the UTF-8 BOM !
				// Ref: http://stackoverflow.com/questions/2223882/whats-different-between-utf-8-and-utf-8-without-bom

				InputStream passwordFile = this.GetType().getResourceAsStream("unicode/" + "passphrase_cyr.txt");
				Reader reader = new InputStreamReader(passwordFile, Charset.forName("UTF-8"));
				BufferedReader @in = new BufferedReader(reader);
				string passphrase = @in.readLine();
				@in.close();
				passwordFile.close();

				test_key(keyId, passphrase);

				// all fine!

			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
				fail(e.Message);
			}
		}

		private PGPSecretKeyRingCollection loadSecretKeyCollection(string keyName)
		{
			return new PGPSecretKeyRingCollection(this.GetType().getResourceAsStream("unicode/" + keyName), new JcaKeyFingerprintCalculator());
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("Unicode Password tests");

			suite.addTestSuite(typeof(PGPUnicodeTest));

			return suite;
		}
	}

}