﻿namespace org.bouncycastle.crypto.test
{
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// test for PKCS12 key generation - vectors from 
	/// <a href=http://www.drh-consultancy.demon.co.uk/test.txt>
	/// http://www.drh-consultancy.demon.co.uk/test.txt</a>
	/// </summary>
	public class PKCS12Test : Test
	{
		internal char[] password1 = new char[] {'s', 'm', 'e', 'g'};
		internal char[] password2 = new char[] {'q', 'u', 'e', 'e', 'g'};

		private bool isEqual(byte[] a, byte[] b)
		{
			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		private TestResult run1(int id, char[] password, byte[] salt, int iCount, byte[] result)
		{
			PBEParametersGenerator generator = new PKCS12ParametersGenerator(new SHA1Digest());

			generator.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iCount);

			CipherParameters key = generator.generateDerivedParameters(24 * 8);

			if (isEqual(result, ((KeyParameter)key).getKey()))
			{
				return new SimpleTestResult(true, "PKCS12Test: Okay");
			}
			else
			{
				return new SimpleTestResult(false, "PKCS12Test: id " + id + " Failed");
			}
		}

		private TestResult run2(int id, char[] password, byte[] salt, int iCount, byte[] result)
		{
			PBEParametersGenerator generator = new PKCS12ParametersGenerator(new SHA1Digest());

			generator.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iCount);

			ParametersWithIV @params = (ParametersWithIV)generator.generateDerivedParameters(64, 64);

			if (isEqual(result, @params.getIV()))
			{
				return new SimpleTestResult(true, "PKCS12Test: Okay");
			}
			else
			{
				return new SimpleTestResult(false, "PKCS12Test: id " + id + " Failed");
			}
		}

		private TestResult run3(int id, char[] password, byte[] salt, int iCount, byte[] result)
		{
			PBEParametersGenerator generator = new PKCS12ParametersGenerator(new SHA1Digest());

			generator.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iCount);

			CipherParameters key = generator.generateDerivedMacParameters(160);

			if (isEqual(result, ((KeyParameter)key).getKey()))
			{
				return new SimpleTestResult(true, "PKCS12Test: Okay");
			}
			else
			{
				return new SimpleTestResult(false, "PKCS12Test: id " + id + " Failed");
			}
		}

		public virtual string getName()
		{
			return "PKCS12Test";
		}

		public virtual TestResult perform()
		{
			TestResult result;

			result = run1(1, password1, Hex.decode("0A58CF64530D823F"), 1, Hex.decode("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3"));

			if (result.isSuccessful())
			{
				result = run2(2, password1, Hex.decode("0A58CF64530D823F"), 1, Hex.decode("79993DFE048D3B76"));
			}

			if (result.isSuccessful())
			{
				result = run1(3, password1, Hex.decode("642B99AB44FB4B1F"), 1, Hex.decode("F3A95FEC48D7711E985CFE67908C5AB79FA3D7C5CAA5D966"));
			}

			if (result.isSuccessful())
			{
				result = run2(4, password1, Hex.decode("642B99AB44FB4B1F"), 1, Hex.decode("C0A38D64A79BEA1D"));
			}

			if (result.isSuccessful())
			{
				result = run3(5, password1, Hex.decode("3D83C0E4546AC140"), 1, Hex.decode("8D967D88F6CAA9D714800AB3D48051D63F73A312"));
			}

			if (result.isSuccessful())
			{
				result = run1(6, password2, Hex.decode("05DEC959ACFF72F7"), 1000, Hex.decode("ED2034E36328830FF09DF1E1A07DD357185DAC0D4F9EB3D4"));
			}

			if (result.isSuccessful())
			{
				result = run2(7, password2, Hex.decode("05DEC959ACFF72F7"), 1000, Hex.decode("11DEDAD7758D4860"));
			}

			if (result.isSuccessful())
			{
				result = run1(8, password2, Hex.decode("1682C0FC5B3F7EC5"), 1000, Hex.decode("483DD6E919D7DE2E8E648BA8F862F3FBFBDC2BCB2C02957F"));
			}

			if (result.isSuccessful())
			{
				result = run2(9, password2, Hex.decode("1682C0FC5B3F7EC5"), 1000, Hex.decode("9D461D1B00355C50"));
			}

			if (result.isSuccessful())
			{
				result = run3(10, password2, Hex.decode("263216FCC2FAB31C"), 1000, Hex.decode("5EC4C7A80DF652294C3925B6489A7AB857C83476"));
			}

			return result;
		}

		public static void Main(string[] args)
		{
			PKCS12Test test = new PKCS12Test();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}