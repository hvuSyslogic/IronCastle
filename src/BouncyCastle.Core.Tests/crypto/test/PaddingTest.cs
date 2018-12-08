using System;

namespace org.bouncycastle.crypto.test
{

	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using BlockCipherPadding = org.bouncycastle.crypto.paddings.BlockCipherPadding;
	using ISO10126d2Padding = org.bouncycastle.crypto.paddings.ISO10126d2Padding;
	using ISO7816d4Padding = org.bouncycastle.crypto.paddings.ISO7816d4Padding;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using TBCPadding = org.bouncycastle.crypto.paddings.TBCPadding;
	using X923Padding = org.bouncycastle.crypto.paddings.X923Padding;
	using ZeroBytePadding = org.bouncycastle.crypto.paddings.ZeroBytePadding;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// General Padding tests.
	/// </summary>
	public class PaddingTest : SimpleTest
	{
		public PaddingTest()
		{
		}

		private void blockCheck(PaddedBufferedBlockCipher cipher, BlockCipherPadding padding, KeyParameter key, byte[] data)
		{
			byte[] @out = new byte[data.Length + 8];
			byte[] dec = new byte[data.Length];

			try
			{
				cipher.init(true, key);

				int len = cipher.processBytes(data, 0, data.Length, @out, 0);

				len += cipher.doFinal(@out, len);

				cipher.init(false, key);

				int decLen = cipher.processBytes(@out, 0, len, dec, 0);

				decLen += cipher.doFinal(dec, decLen);

				if (!areEqual(data, dec))
				{
					fail("failed to decrypt - i = " + data.Length + ", padding = " + padding.getPaddingName());
				}
			}
			catch (Exception e)
			{
				fail("Exception - " + e.ToString(), e);
			}
		}

		public virtual void testPadding(BlockCipherPadding padding, SecureRandom rand, byte[] ffVector, byte[] ZeroVector)
		{
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new DESEngine(), padding);
			KeyParameter key = new KeyParameter(Hex.decode("0011223344556677"));

			//
			// ff test
			//
			byte[] data = new byte[] {unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), (byte)0, (byte)0, (byte)0, (byte)0, (byte)0};

			if (ffVector != null)
			{
				padding.addPadding(data, 3);

				if (!areEqual(data, ffVector))
				{
					fail("failed ff test for " + padding.getPaddingName());
				}
			}

			//
			// zero test
			//
			if (ZeroVector != null)
			{
				data = new byte[8];
				padding.addPadding(data, 4);

				if (!areEqual(data, ZeroVector))
				{
					fail("failed zero test for " + padding.getPaddingName());
				}
			}

			for (int i = 1; i != 200; i++)
			{
				data = new byte[i];

				rand.nextBytes(data);

				blockCheck(cipher, padding, key, data);
			}
		}

		private void testOutputSizes()
		{
			PaddedBufferedBlockCipher bc = new PaddedBufferedBlockCipher(new DESEngine(), new PKCS7Padding());
			KeyParameter key = new KeyParameter(Hex.decode("0011223344556677"));

			for (int i = 0; i < bc.getBlockSize() * 2; i++)
			{
				bc.init(true, key);
				if (bc.getUpdateOutputSize(i) < 0)
				{
					fail("Padded cipher encrypt negative update output size for input size " + i);
				}
				if (bc.getOutputSize(i) < 0)
				{
					fail("Padded cipher encrypt negative output size for input size " + i);
				}

				bc.init(false, key);
				if (bc.getUpdateOutputSize(i) < 0)
				{
					fail("Padded cipher decrypt negative update output size for input size " + i);
				}
				if (bc.getOutputSize(i) < 0)
				{
					fail("Padded cipher decrypt negative output size for input size " + i);
				}

			}
		}

		public override void performTest()
		{
			SecureRandom rand = new SecureRandom(new byte[20]);

			rand.setSeed(System.currentTimeMillis());

			testPadding(new PKCS7Padding(), rand, Hex.decode("ffffff0505050505"), Hex.decode("0000000004040404"));

			PKCS7Padding padder = new PKCS7Padding();
			try
			{
				padder.padCount(new byte[8]);

				fail("invalid padding not detected");
			}
			catch (InvalidCipherTextException e)
			{
				if (!"pad block corrupted".Equals(e.Message))
				{
					fail("wrong exception for corrupt padding: " + e);
				}
			}

			testPadding(new ISO10126d2Padding(), rand, null, null);

			testPadding(new X923Padding(), rand, null, null);

			testPadding(new TBCPadding(), rand, Hex.decode("ffffff0000000000"), Hex.decode("00000000ffffffff"));

			testPadding(new ZeroBytePadding(), rand, Hex.decode("ffffff0000000000"), null);

			testPadding(new ISO7816d4Padding(), rand, Hex.decode("ffffff8000000000"), Hex.decode("0000000080000000"));

			testOutputSizes();

		}

		public override string getName()
		{
			return "PaddingTest";
		}

		public static void Main(string[] args)
		{
			runTest(new PaddingTest());
		}
	}

}