using System;

namespace org.bouncycastle.jce.provider.test
{


	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class WrapTest : Test
	{
		public virtual TestResult perform()
		{
			try
			{
				Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
				KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
				fact.initialize(512, new SecureRandom());

				KeyPair keyPair = fact.generateKeyPair();

				PrivateKey priKey = keyPair.getPrivate();
				PublicKey pubKey = keyPair.getPublic();

				KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");
				Key wrapKey = keyGen.generateKey();
				cipher.init(Cipher.WRAP_MODE, wrapKey);
				byte[] wrappedKey = cipher.wrap(priKey);

				cipher.init(Cipher.UNWRAP_MODE, wrapKey);
				Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);

				if (!MessageDigest.isEqual(priKey.getEncoded(), key.getEncoded()))
				{
					return new SimpleTestResult(false, "Unwrapped key does not match");
				}

				return new SimpleTestResult(true, getName() + ": Okay");
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": exception - " + e.ToString(), e);
			}
		}

		public virtual string getName()
		{
			return "WrapTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			Test test = new WrapTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result.ToString());
			if (result.getException() != null)
			{
				Console.WriteLine(result.getException().ToString());
				Console.Write(result.getException().StackTrace);
			}
		}
	}

}