using System;

namespace org.bouncycastle.jce.provider.test
{


	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// check that doFinal is properly reseting the cipher.
	/// </summary>
	public class DoFinalTest : Test
	{
		public DoFinalTest()
		{
		}

		private bool equalArray(byte[] a, int aOff, byte[] b, int length)
		{
			if (aOff + a.Length < length)
			{
				return false;
			}

			if (b.Length < length)
			{
				return false;
			}

			for (int i = 0; i != length; i++)
			{
				if (a[aOff + i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public virtual TestResult checkCipher(string cipherName)
		{
			string lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";
			string baseAlgorithm;
			int index = cipherName.IndexOf('/');

			if (index > 0)
			{
				baseAlgorithm = cipherName.Substring(0, index);
			}
			else
			{
				baseAlgorithm = cipherName;
			}

			try
			{
				KeyGenerator kGen = KeyGenerator.getInstance(baseAlgorithm, "BC");
				Cipher cipher = Cipher.getInstance(cipherName, "BC");
				Key key = kGen.generateKey();

				cipher.init(Cipher.ENCRYPT_MODE, key);

				byte[] encrypted = cipher.doFinal(lCode.GetBytes());

				// 2nd try
				byte[] encrypted2 = cipher.doFinal(lCode.GetBytes());

				if (encrypted.Length != encrypted2.Length)
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.Length + " got " + encrypted2.Length);
				}

				if (!equalArray(encrypted, 0, encrypted2, encrypted.Length))
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - first two arrays not equal");
				}

				// 3rd try
				byte[] enc1 = cipher.update(lCode.GetBytes());
				byte[] enc2 = cipher.doFinal();

				if ((enc1.Length + enc2.Length) != encrypted.Length)
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.Length + " got " + (enc1.Length + enc2.Length));
				}

				if (!equalArray(encrypted, 0, enc1, enc1.Length))
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - enc1 array not equal");
				}

				if (!equalArray(encrypted, enc1.Length, enc2, enc2.Length))
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - enc1 array not equal");
				}

				enc1 = cipher.update(lCode.GetBytes());

				if (!equalArray(encrypted, 0, enc1, enc1.Length))
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - 2nd enc1 array not equal");
				}

				int len = cipher.doFinal(enc1, 0);
				if ((enc1.Length + len) != encrypted.Length)
				{
					return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.Length + " got " + (enc1.Length + len));
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - exception " + e.ToString());
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual TestResult perform()
		{
			TestResult result = checkCipher("RC4");

			if (!result.isSuccessful())
			{
				return result;
			}

			result = checkCipher("DES/CBC/PKCS5Padding");

			if (!result.isSuccessful())
			{
				return result;
			}

			return checkCipher("Rijndael");
		}

		public virtual string getName()
		{
			return "DoFinalTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			Test test = new DoFinalTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result.ToString());
		}
	}

}