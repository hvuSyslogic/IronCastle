using System;

namespace org.bouncycastle.jce.provider.test
{


	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public class GMacTest : SimpleTest
	{
		public override string getName()
		{
			return "GMac";
		}

		public override void performTest()
		{
			checkRegistrations();
		}

		private void checkRegistrations()
		{
			List missingMacs = new ArrayList();
			List missingKeyGens = new ArrayList();

			string[] ciphers = new string[] {"AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Tnepres", "Serpent", "SM4", "RC6", "CAMELLIA"};
			string[] macs = new string[] {"a52308801b32d4770c701ace9b826f12", "cf11dacaf6024a78dba76b256e23caab", "13db7c428e5a7128149b5ec782d07fac", "d13a33e78e48b274bf7d64bf9aecdb82", "d05d550054735c6e7e01b6981fc14b4e", "4a34dfe4f5410afd7c40b1e110377a73", "80c3cc898899e41fd4e21c6c1261fedb", "d394f3d12bec3cf6c5302265ecab9af1", "d9f597c96b41f641da6c83d4760f543b", "371ad8cc920c6bda2a26d8f237bd446b"};

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
				// GCM is defined over 128 bit block ciphers
				if (blocksize == 16)
				{
					string macName = cipherName + "-GMAC";
					string macNameAlt = cipherName + "GMAC";

					// Check we have a GMAC registered for each name
					checkMac(macName, missingMacs, missingKeyGens, macs[i]);
					checkMac(macNameAlt, missingMacs, missingKeyGens, macs[i]);
				}
			}
			if (missingMacs.size() != 0)
			{
				fail("Did not find GMAC registrations for the following ciphers: " + missingMacs);
			}
			if (missingKeyGens.size() != 0)
			{
				fail("Did not find GMAC KeyGenerator registrations for the following macs: " + missingKeyGens);
			}
		}

		private void checkMac(string name, List missingMacs, List missingKeyGens, string macOutput)
		{
			try
			{
				Mac mac = Mac.getInstance(name);

				mac.init(new SecretKeySpec(new byte[mac.getMacLength()], mac.getAlgorithm()), new IvParameterSpec(new byte[16]));
				mac.update(new byte[128]);
				byte[] bytes = mac.doFinal();

				if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
				{
					fail("wrong mac value computed for " + name + " " + Hex.toHexString(bytes));
				}

				try
				{
					KeyGenerator kg = KeyGenerator.getInstance(name);
					kg.generateKey();
				}
				catch (NoSuchAlgorithmException)
				{
					missingKeyGens.add(name);
				}
			}
			catch (NoSuchAlgorithmException)
			{
				missingMacs.add(name);
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

			runTest(new GMacTest());
		}
	}
}