﻿using System;

namespace org.bouncycastle.jce.provider.test
{


	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	/// <summary>
	/// check that cipher input/output streams are working correctly
	/// </summary>
	public class CipherStreamTest : SimpleTest
	{

		private static byte[] RK = Hex.decode("0123456789ABCDEF");
		private static byte[] RIN = Hex.decode("4e6f772069732074");
		private static byte[] ROUT = Hex.decode("3afbb5c77938280d");

		private static byte[] SIN = Hex.decode("00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000");
		private static readonly byte[] SK = Hex.decode("80000000000000000000000000000000");
		private static readonly byte[] SIV = Hex.decode("0000000000000000");
		private static readonly byte[] SOUT = Hex.decode("4DFA5E481DA23EA09A31022050859936" + "DA52FCEE218005164F267CB65F5CFD7F" + "2B4F97E0FF16924A52DF269515110A07" + "F9E460BC65EF95DA58F740B7D1DBB0AA");

		private static readonly byte[] XSK = Hex.decode("d5c7f6797b7e7e9c1d7fd2610b2abf2bc5a7885fb3ff78092fb3abe8986d35e2");
		private static readonly byte[] XSIV = Hex.decode("744e17312b27969d826444640e9c4a378ae334f185369c95");
		private static readonly byte[] XSIN = Hex.decode("7758298c628eb3a4b6963c5445ef66971222be5d1a4ad839715d1188071739b77cc6e05d5410f963a64167629757");
		private static readonly byte[] XSOUT = Hex.decode("27b8cfe81416a76301fd1eec6a4d99675069b2da2776c360db1bdfea7c0aa613913e10f7a60fec04d11e65f2d64e");

		private static readonly byte[] CHAK = Hex.decode("80000000000000000000000000000000");
		private static readonly byte[] CHAIV = Hex.decode("0000000000000000");
		private static readonly byte[] CHAIN = Hex.decode("00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000");
		private static readonly byte[] CHAOUT = Hex.decode("FBB87FBB8395E05DAA3B1D683C422046" + "F913985C2AD9B23CFC06C1D8D04FF213" + "D44A7A7CDB84929F915420A8A3DC58BF" + "0F7ECB4B1F167BB1A5E6153FDAF4493D");

		private static readonly byte[] CHA7539K = Hex.decode("8000000000000000000000000000000080000000000000000000000000000000");
		private static readonly byte[] CHA7539IV = Hex.decode("000000000000000000000000");
		private static readonly byte[] CHA7539IN = Hex.decode("00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000" + "00000000000000000000000000000000");
		private static readonly byte[] CHA7539OUT = Hex.decode("aef50e541e12a65dc21e90ebb4c03987971c540f78eb536df692ff89fc47561ed17eb23b63eb714c09d0c50af703e01485926c140e994b3edff9df635a91d268");

		private static readonly byte[] HCIN = new byte[64];
		private static readonly byte[] HCIV = new byte[32];

		private static readonly byte[] HCK256A = new byte[32];
		private static readonly byte[] HC256A = Hex.decode("5B078985D8F6F30D42C5C02FA6B67951" + "53F06534801F89F24E74248B720B4818" + "CD9227ECEBCF4DBF8DBF6977E4AE14FA" + "E8504C7BC8A9F3EA6C0106F5327E6981");

		private static readonly byte[] HCK128A = new byte[16];
		private static readonly byte[] HC128A = Hex.decode("82001573A003FD3B7FD72FFB0EAF63AA" + "C62F12DEB629DCA72785A66268EC758B" + "1EDB36900560898178E0AD009ABF1F49" + "1330DC1C246E3D6CB264F6900271D59C");

		private static readonly byte[] GRAIN_V1 = Hex.decode("0123456789abcdef1234");
		private static readonly byte[] GRAIN_V1_IV = Hex.decode("0123456789abcdef");
		private static readonly byte[] GRAIN_V1_IN = new byte[10];
		private static readonly byte[] GRAIN_V1_OUT = Hex.decode("7f362bd3f7abae203664");

		private static readonly byte[] GRAIN_128 = Hex.decode("0123456789abcdef123456789abcdef0");
		private static readonly byte[] GRAIN_128_IV = Hex.decode("0123456789abcdef12345678");
		private static readonly byte[] GRAIN_128_IN = new byte[16];
		private static readonly byte[] GRAIN_128_OUT = Hex.decode("afb5babfa8de896b4b9c6acaf7c4fbfd");

		public CipherStreamTest()
		{
		}

		private void runTest(string name)
		{
			string lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";
			KeyGenerator kGen;

			if (name.IndexOf('/') < 0)
			{
				kGen = KeyGenerator.getInstance(name, "BC");
			}
			else
			{
				kGen = KeyGenerator.getInstance(name.Substring(0, name.IndexOf('/')), "BC");
			}

			byte[] data = lCode.GetBytes();
			Cipher @in = Cipher.getInstance(name, "BC");
			Cipher @out = Cipher.getInstance(name, "BC");
			Key key = kGen.generateKey();
			ByteArrayInputStream bIn = new ByteArrayInputStream(data);
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			@in.init(Cipher.ENCRYPT_MODE, key);
			if (@in.getIV() != null)
			{
				@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(@in.getIV()));
			}
			else
			{
				@out.init(Cipher.DECRYPT_MODE, key);
			}

			CipherInputStream cIn = new CipherInputStream(bIn, @in);
			CipherOutputStream cOut = new CipherOutputStream(bOut, @out);

			int c;

			while ((c = cIn.read()) >= 0)
			{
				cOut.write(c);
			}

			cIn.close();

			cOut.flush();
			cOut.close();

			string res = StringHelper.NewString(bOut.toByteArray());

			if (!res.Equals(lCode))
			{
				fail("Failed - decrypted data doesn't match.");
			}


			//
			// short buffer test
			//
			try
			{
				byte[] enc = @in.doFinal(data);
				byte[] out1 = new byte[enc.Length / 2];

				try
				{
					@out.doFinal(enc, 0, enc.Length, out1, 0);

					fail("ShortBufferException not triggered");
				}
				catch (ShortBufferException)
				{
					byte[] out2 = new byte[@in.getOutputSize(enc.Length)];

					int count = @out.doFinal(enc, 0, enc.Length, out2, 0);

					if (!areEqual(out2, count, data))
					{
						fail("" + name + " failed decryption - expected " + StringHelper.NewString(Hex.encode(data)) + " got " + StringHelper.NewString(Hex.encode(out2)));
					}
				}
			}
			catch (TestFailedException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				fail("" + name + " failed short buffer decryption - " + e.ToString());
			}
		}


		private bool areEqual(byte[] a, int aLen, byte[] b)
		{
			if (b.Length != aLen)
			{
				return false;
			}

			for (int i = 0; i != aLen; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		private void testAlgorithm(string name, byte[] keyBytes, byte[] iv, byte[] plainText, byte[] cipherText)
		{
			SecretKey key = new SecretKeySpec(keyBytes, name);
			Cipher @in = Cipher.getInstance(name, "BC");
			Cipher @out = Cipher.getInstance(name, "BC");

			if (iv != null)
			{
				@in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
				@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			}
			else
			{
				@in.init(Cipher.ENCRYPT_MODE, key);
				@out.init(Cipher.DECRYPT_MODE, key);
			}

			byte[] enc = @in.doFinal(plainText);
			if (!areEqual(enc, cipherText))
			{
				fail(name + ": cipher text doesn't match got " + StringHelper.NewString(Hex.encode(enc)));
			}

			byte[] dec = @out.doFinal(enc);

			if (!areEqual(dec, plainText))
			{
				fail(name + ": plain text doesn't match");
			}
		}

		private void testException(string name)
		{
			try
			{
				byte[] key128 = new byte[] {unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143), unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143)};

				byte[] key256 = new byte[] {unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143), unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143), unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143), unchecked((byte)128), unchecked((byte)131), unchecked((byte)133), unchecked((byte)134), unchecked((byte)137), unchecked((byte)138), unchecked((byte)140), unchecked((byte)143)};

				byte[] keyBytes;
				if (name.Equals("HC256") || name.Equals("XSalsa20") || name.Equals("ChaCha7539"))
				{
					keyBytes = key256;
				}
				else
				{
					keyBytes = key128;
				}

				SecretKeySpec cipherKey = new SecretKeySpec(keyBytes, name);
				Cipher ecipher = Cipher.getInstance(name, "BC");
				ecipher.init(Cipher.ENCRYPT_MODE, cipherKey);

				byte[] cipherText = new byte[0];
				try
				{
					// According specification Method engineUpdate(byte[] input,
					// int inputOffset, int inputLen, byte[] output, int
					// outputOffset)
					// throws ShortBufferException - if the given output buffer is
					// too
					// small to hold the result
					ecipher.update(new byte[20], 0, 20, cipherText);

					fail("failed exception test - no ShortBufferException thrown");
				}
				catch (ShortBufferException)
				{
					// ignore
				}

				try
				{
					Cipher c = Cipher.getInstance(name, "BC");

					Key k = new PublicKeyAnonymousInnerClass(this);

					c.init(Cipher.ENCRYPT_MODE, k);

					fail("failed exception test - no InvalidKeyException thrown for public key");
				}
				catch (InvalidKeyException)
				{
					// okay
				}

				try
				{
					Cipher c = Cipher.getInstance(name, "BC");

					Key k = new PrivateKeyAnonymousInnerClass(this);

					c.init(Cipher.DECRYPT_MODE, k);

					fail("failed exception test - no InvalidKeyException thrown for private key");
				}
				catch (InvalidKeyException)
				{
					// okay
				}
			}
			catch (Exception e)
			{
				fail("unexpected exception.", e);
			}
		}

		public class PublicKeyAnonymousInnerClass : PublicKey
		{
			private readonly CipherStreamTest outerInstance;

			public PublicKeyAnonymousInnerClass(CipherStreamTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}


			public string getAlgorithm()
			{
				return "STUB";
			}

			public string getFormat()
			{
				return null;
			}

			public byte[] getEncoded()
			{
				return null;
			}

		}

		public class PrivateKeyAnonymousInnerClass : PrivateKey
		{
			private readonly CipherStreamTest outerInstance;

			public PrivateKeyAnonymousInnerClass(CipherStreamTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}


			public string getAlgorithm()
			{
				return "STUB";
			}

			public string getFormat()
			{
				return null;
			}

			public byte[] getEncoded()
			{
				return null;
			}

		}

		public override void performTest()
		{
			runTest("RC4");
			testException("RC4");
			testAlgorithm("RC4", RK, null, RIN, ROUT);
			runTest("Salsa20");
			testException("Salsa20");
			testAlgorithm("Salsa20", SK, SIV, SIN, SOUT);
			runTest("XSalsa20");
			testException("XSalsa20");
			testAlgorithm("XSalsa20", XSK, XSIV, XSIN, XSOUT);
			runTest("ChaCha");
			testException("ChaCha");
			testAlgorithm("ChaCha", CHAK, CHAIV, CHAIN, CHAOUT);
			runTest("ChaCha7539");
			testException("ChaCha7539");
			testAlgorithm("ChaCha7539", CHA7539K, CHA7539IV, CHA7539IN, CHA7539OUT);
			runTest("HC128");
			testException("HC128");
			testAlgorithm("HC128", HCK128A, HCIV, HCIN, HC128A);
			runTest("HC256");
			testException("HC256");
			testAlgorithm("HC256", HCK256A, HCIV, HCIN, HC256A);
			runTest("VMPC");
			testException("VMPC");
			//testAlgorithm("VMPC", a, iv, in, a);
			runTest("VMPC-KSA3");
			testException("VMPC-KSA3");
			//testAlgorithm("VMPC-KSA3", a, iv, in, a);
			testAlgorithm("Grainv1", GRAIN_V1, GRAIN_V1_IV, GRAIN_V1_IN, GRAIN_V1_OUT);
			testAlgorithm("Grain128", GRAIN_128, GRAIN_128_IV, GRAIN_128_IN, GRAIN_128_OUT);
			runTest("DES/ECB/PKCS7Padding");
			runTest("DES/CFB8/NoPadding");
		}

		public override string getName()
		{
			return "CipherStreamTest";
		}


		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new CipherStreamTest());
		}
	}

}