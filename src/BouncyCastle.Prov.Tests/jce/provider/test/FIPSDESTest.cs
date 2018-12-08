using System;

namespace org.bouncycastle.jce.provider.test
{


	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// basic FIPS test class for a block cipher, just to make sure ECB/CBC/OFB/CFB are behaving
	/// correctly. Tests from <a href=http://www.itl.nist.gov/fipspubs/fip81.htm>FIPS 81</a>.
	/// </summary>
	public class FIPSDESTest : Test
	{
		internal static string[] fips1Tests = new string[] {"DES/ECB/NoPadding", "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53", "DES/CBC/NoPadding", "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6", "DES/CFB/NoPadding", "f3096249c7f46e51a69e839b1a92f78403467133898ea622"};

		internal static string[] fips2Tests = new string[] {"DES/CFB8/NoPadding", "f31fda07011462ee187f", "DES/OFB8/NoPadding", "f34a2850c9c64985d684"};

		internal static byte[] input1 = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");
		internal static byte[] input2 = Hex.decode("4e6f7720697320746865");

		public virtual string getName()
		{
			return "FIPSDESTest";
		}

		private bool equalArray(byte[] a, byte[] b)
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

		public virtual TestResult test(string algorithm, byte[] input, byte[] output)
		{
			Key key;
			Cipher @in, @out;
			CipherInputStream cIn;
			CipherOutputStream cOut;
			ByteArrayInputStream bIn;
			ByteArrayOutputStream bOut;
			IvParameterSpec spec = new IvParameterSpec(Hex.decode("1234567890abcdef"));

			try
			{
				string baseAlgorithm;

				key = new SecretKeySpec(Hex.decode("0123456789abcdef"), "DES");

				@in = Cipher.getInstance(algorithm, "BC");
				@out = Cipher.getInstance(algorithm, "BC");

				if (algorithm.StartsWith("DES/ECB", StringComparison.Ordinal))
				{
					@out.init(Cipher.ENCRYPT_MODE, key);
				}
				else
				{
					@out.init(Cipher.ENCRYPT_MODE, key, spec);
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed initialisation - " + e.ToString(), e);
			}

			try
			{
				if (algorithm.StartsWith("DES/ECB", StringComparison.Ordinal))
				{
					@in.init(Cipher.DECRYPT_MODE, key);
				}
				else
				{
					@in.init(Cipher.DECRYPT_MODE, key, spec);
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed initialisation - " + e.ToString(), e);
			}

			//
			// encryption pass
			//
			bOut = new ByteArrayOutputStream();

			cOut = new CipherOutputStream(bOut, @out);

			try
			{
				for (int i = 0; i != input.Length / 2; i++)
				{
					cOut.write(input[i]);
				}
				cOut.write(input, input.Length / 2, input.Length - input.Length / 2);
				cOut.close();
			}
			catch (IOException e)
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - " + e.ToString());
			}

			byte[] bytes;

			bytes = bOut.toByteArray();

			if (!equalArray(bytes, output))
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - expected " + StringHelper.NewString(Hex.encode(output)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			//
			// decryption pass
			//
			bIn = new ByteArrayInputStream(bytes);

			cIn = new CipherInputStream(bIn, @in);

			try
			{
				DataInputStream dIn = new DataInputStream(cIn);

				bytes = new byte[input.Length];

				for (int i = 0; i != input.Length / 2; i++)
				{
					bytes[i] = (byte)dIn.read();
				}
				dIn.readFully(bytes, input.Length / 2, bytes.Length - input.Length / 2);
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed encryption - " + e.ToString());
			}

			if (!equalArray(bytes, input))
			{
				return new SimpleTestResult(false, getName() + ": " + algorithm + " failed decryption - expected " + StringHelper.NewString(Hex.encode(input)) + " got " + StringHelper.NewString(Hex.encode(bytes)));
			}

			return new SimpleTestResult(true, getName() + ": " + algorithm + " Okay");
		}

		public virtual TestResult perform()
		{
			for (int i = 0; i != fips1Tests.Length; i += 2)
			{
				TestResult result;

				result = test(fips1Tests[i], input1, Hex.decode(fips1Tests[i + 1]));
				if (!result.isSuccessful())
				{
					return result;
				}
			}

			for (int i = 0; i != fips2Tests.Length; i += 2)
			{
				TestResult result;

				result = test(fips2Tests[i], input2, Hex.decode(fips2Tests[i + 1]));
				if (!result.isSuccessful())
				{
					return result;
				}
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			Test test = new FIPSDESTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result.ToString());
		}
	}

}