using System;

namespace org.bouncycastle.jce.provider.test
{


	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public class Poly1305Test : SimpleTest
	{
		private static readonly byte[] MASTER_KEY = Hex.decode("01bcb20bfc8b6e03609ddd09f44b060f" + "95cc0e44d0b79a8856afcae1bec4fe3c");

		public override string getName()
		{
			return "Poly1305";
		}

		public override void performTest()
		{
			checkRawPoly1305();
			checkRegistrations();
		}

		private void checkRegistrations()
		{
			List missingMacs = new ArrayList();
			List missingKeyGens = new ArrayList();

			string[] ciphers = new string[]{"AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Serpent", "SM4", "RC6", "CAMELLIA"};
			string[] macs = new string[]{"4bb5e21dd13001ed5faccfcfdaf8a854", "6d601be3d5ebbb9972a64ed3223d913d", "211195296d9afc7b35a1223a79487c87", "f328857a1b653684e73760c804c55b1d", "21cd8adb23ca84eb4dbb12780595bf28", "c218102702d8a2ee5c9ef9000e91454d", "9bb04be6a1c314a9054ae3c94d3c941b", "db86de7b1fcae429753d68b1263d7ca0", "11918174f33a2f278fb86554da094112"};

			for (int i = 0; i < ciphers.Length; i++)
			{
				string cipherName = ciphers[i];
				Cipher cipher;
				try
				{
					cipher = Cipher.getInstance(cipherName, "BC");
				}
				catch (Exception e)
				{
					JavaSystem.err.println(cipherName + ": " + e.Message);
					continue;
				}
				int blocksize;
				try
				{
					blocksize = cipher.getBlockSize();
				}
				catch (Exception e)
				{
					JavaSystem.err.println(cipherName + ": " + e.Message);
					continue;
				}
				// Poly1305 is defined over 128 bit block ciphers
				if (blocksize == 16)
				{
					string macName = "Poly1305-" + cipherName;
					string macNameAlt = "Poly1305" + cipherName;

					// Check we have a Poly1305 registered for each name
					checkMac(macName, missingMacs, missingKeyGens, macs[i]);
					checkMac(macNameAlt, missingMacs, missingKeyGens, macs[i]);
				}
			}
			if (missingMacs.size() != 0)
			{
				fail("Did not find Poly1305 registrations for the following ciphers: " + missingMacs);
			}
			if (missingKeyGens.size() != 0)
			{
				fail("Did not find Poly1305 KeyGenerator registrations for the following macs: " + missingKeyGens);
			}
		}

		private void checkRawPoly1305()
		{
			checkMac("Poly1305", "e8bd1466eaf442dd71598370c1e34392");
		}

		private void checkMac(string name, string macOutput)
		{
			KeyGenerator kg = KeyGenerator.getInstance(name);
			SecretKey key = kg.generateKey();

			try
			{
				Poly1305KeyGenerator.checkKey(key.getEncoded());
			}
			catch (IllegalArgumentException)
			{
				fail("Generated key for algo " + name + " does not match required Poly1305 format.");
			}

			Mac mac = Mac.getInstance(name);
			mac.init(new SecretKeySpec(MASTER_KEY, name));
			mac.update(new byte[128]);
			byte[] bytes = mac.doFinal();

			if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
			{
				fail("wrong mac value computed for " + name, macOutput, StringHelper.NewString(Hex.encode(bytes)));
			}
		}

		private void checkMac(string name, List missingMacs, List missingKeyGens, string macOutput)
		{
			try
			{
				try
				{
					KeyGenerator kg = KeyGenerator.getInstance(name);
					SecretKey key = kg.generateKey();

					try
					{
						Poly1305KeyGenerator.checkKey(key.getEncoded());
					}
					catch (IllegalArgumentException)
					{
						fail("Generated key for algo " + name + " does not match required Poly1305 format.");
					}

					try
					{
						Mac mac = Mac.getInstance(name);
						mac.init(new SecretKeySpec(MASTER_KEY, name), new IvParameterSpec(new byte[16]));
						mac.update(new byte[128]);
						byte[] bytes = mac.doFinal();

						if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
						{
							fail("wrong mac value computed for " + name, macOutput, StringHelper.NewString(Hex.encode(bytes)));
						}
					}
					catch (NoSuchAlgorithmException)
					{
						missingMacs.add(name);
					}

				}
				catch (NoSuchAlgorithmException)
				{
					missingKeyGens.add(name);
				}
			}
			catch (TestFailedException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				fail("Unexpected error", e);
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new Poly1305Test());
		}
	}
}