using System;

namespace org.bouncycastle.crypto.test
{

	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using AESFastEngine = org.bouncycastle.crypto.engines.AESFastEngine;
	using AESLightEngine = org.bouncycastle.crypto.engines.AESLightEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// Test vectors from the NIST standard tests and Brian Gladman's vector set
	/// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">
	/// http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
	/// </summary>
	public class AESVectorFileTest : Test
	{

		private int countOfTests = 0;
		private int testNum = 0;

		public virtual BlockCipher createNewEngineForTest()
		{
			return new AESEngine();
		}

		private Test[] readTestVectors(InputStream inStream)
		{
			// initialize key, plaintext, ciphertext = null
			// read until find BLOCKSIZE=
			// return if not 128
			// read KEYSIZE= or ignore
			// loop
			// read a line
			// if starts with BLOCKSIZE=
			// parse the rest. return if not 128
			// if starts with KEY=
			// parse the rest and set KEY
			// if starts with PT=
			// parse the rest and set plaintext
			// if starts with CT=
			// parse the rest and set ciphertext
			// if starts with TEST= or end of file
			// if key, plaintext, ciphertext are all not null
			// save away their values as the next test
			// until end of file
			List tests = new ArrayList();
			string key = null;
			string plaintext = null;
			string ciphertext = null;

			BufferedReader @in = new BufferedReader(new InputStreamReader(inStream));

			try
			{
				string line = @in.readLine();

				while (!string.ReferenceEquals(line, null))
				{
					line = line.Trim().ToLower();
					if (line.StartsWith("blocksize=", StringComparison.Ordinal))
					{
						int i = 0;
						try
						{
							i = int.Parse(line.Substring(10).Trim());
						}
						catch (Exception)
						{
						}
						if (i != 128)
						{
							return null;
						}
					}
					else if (line.StartsWith("keysize=", StringComparison.Ordinal))
					{
						int i = 0;
						try
						{
							i = int.Parse(line.Substring(10).Trim());
						}
						catch (Exception)
						{
						}
						if ((i != 128) && (i != 192) && (i != 256))
						{
							return null;
						}
					}
					else if (line.StartsWith("key=", StringComparison.Ordinal))
					{
						key = line.Substring(4).Trim();
					}
					else if (line.StartsWith("pt=", StringComparison.Ordinal))
					{
						plaintext = line.Substring(3).Trim();
					}
					else if (line.StartsWith("ct=", StringComparison.Ordinal))
					{
						ciphertext = line.Substring(3).Trim();
					}
					else if (line.StartsWith("test=", StringComparison.Ordinal))
					{
						if ((!string.ReferenceEquals(key, null)) && (!string.ReferenceEquals(plaintext, null)) && (!string.ReferenceEquals(ciphertext, null)))
						{
							tests.add(new BlockCipherVectorTest(testNum++, createNewEngineForTest(), new KeyParameter(Hex.decode(key)), plaintext, ciphertext));
						}
					}

					line = @in.readLine();
				}
				try
				{
					@in.close();
				}
				catch (IOException)
				{
				}
			}
			catch (IOException)
			{
			}
			if ((!string.ReferenceEquals(key, null)) && (!string.ReferenceEquals(plaintext, null)) && (!string.ReferenceEquals(ciphertext, null)))
			{
				tests.add(new BlockCipherVectorTest(testNum++, createNewEngineForTest(), new KeyParameter(Hex.decode(key)), plaintext, ciphertext));
			}
			return (Test[])(tests.toArray(new Test[tests.size()]));
		}

		public virtual string getName()
		{
			return "AES";
		}

		private TestResult performTestsFromZipFile(File zfile)
		{
			try
			{
				ZipFile inZip = new ZipFile(zfile);
				for (Enumeration files = inZip.entries(); files.hasMoreElements();)
				{
					Test[] tests = null;
					try
					{
						tests = readTestVectors(inZip.getInputStream((ZipEntry)(files.nextElement())));
					}
					catch (Exception e)
					{
						return new SimpleTestResult(false, getName() + ": threw " + e);
					}
					if (tests != null)
					{
						for (int i = 0; i != tests.Length; i++)
						{
							TestResult res = tests[i].perform();
							countOfTests++;

							if (!res.isSuccessful())
							{
								return res;
							}
						}
					}
				}
				inZip.close();
				return new SimpleTestResult(true, getName() + ": Okay");
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": threw " + e);
			}
		}

		private static readonly string[] zipFileNames = new string[] {"rijn.tv.ecbnk.zip", "rijn.tv.ecbnt.zip", "rijn.tv.ecbvk.zip", "rijn.tv.ecbvt.zip"};

		public virtual TestResult perform()
		{
			countOfTests = 0;
			for (int i = 0; i < zipFileNames.Length; i++)
			{
				File inf = new File(zipFileNames[i]);
				TestResult res = performTestsFromZipFile(inf);
				if (!res.isSuccessful())
				{
					return res;
				}
			}
			return new SimpleTestResult(true, getName() + ": " + countOfTests + " performed Okay");
		}

		public static void Main(string[] args)
		{
			AESVectorFileTest test = new AESVectorFileTest();
			TestResult result = test.perform();
			JavaSystem.@out.println(result);

			test = new AESLightVectorFileTest();
			result = test.perform();
			JavaSystem.@out.println(result);

			test = new AESFastVectorFileTest();
			result = test.perform();
			JavaSystem.@out.println(result);

		}

		public class AESLightVectorFileTest : AESVectorFileTest
		{
			public override BlockCipher createNewEngineForTest()
			{
				return new AESLightEngine();
			}

			public override string getName()
			{
				return "AESLight";
			}

		}

		public class AESFastVectorFileTest : AESVectorFileTest
		{
			public override BlockCipher createNewEngineForTest()
			{
				return new AESFastEngine();
			}

			public override string getName()
			{
				return "AESFast";
			}

		}
	}

}