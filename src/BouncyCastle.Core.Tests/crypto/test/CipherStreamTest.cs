using System;

namespace org.bouncycastle.crypto.test
{

	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using BlowfishEngine = org.bouncycastle.crypto.engines.BlowfishEngine;
	using CAST5Engine = org.bouncycastle.crypto.engines.CAST5Engine;
	using CAST6Engine = org.bouncycastle.crypto.engines.CAST6Engine;
	using CamelliaEngine = org.bouncycastle.crypto.engines.CamelliaEngine;
	using ChaChaEngine = org.bouncycastle.crypto.engines.ChaChaEngine;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using Grain128Engine = org.bouncycastle.crypto.engines.Grain128Engine;
	using Grainv1Engine = org.bouncycastle.crypto.engines.Grainv1Engine;
	using HC128Engine = org.bouncycastle.crypto.engines.HC128Engine;
	using HC256Engine = org.bouncycastle.crypto.engines.HC256Engine;
	using NoekeonEngine = org.bouncycastle.crypto.engines.NoekeonEngine;
	using RC2Engine = org.bouncycastle.crypto.engines.RC2Engine;
	using RC4Engine = org.bouncycastle.crypto.engines.RC4Engine;
	using RC6Engine = org.bouncycastle.crypto.engines.RC6Engine;
	using SEEDEngine = org.bouncycastle.crypto.engines.SEEDEngine;
	using Salsa20Engine = org.bouncycastle.crypto.engines.Salsa20Engine;
	using SerpentEngine = org.bouncycastle.crypto.engines.SerpentEngine;
	using TEAEngine = org.bouncycastle.crypto.engines.TEAEngine;
	using ThreefishEngine = org.bouncycastle.crypto.engines.ThreefishEngine;
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using XSalsa20Engine = org.bouncycastle.crypto.engines.XSalsa20Engine;
	using XTEAEngine = org.bouncycastle.crypto.engines.XTEAEngine;
	using CipherInputStream = org.bouncycastle.crypto.io.CipherInputStream;
	using CipherOutputStream = org.bouncycastle.crypto.io.CipherOutputStream;
	using InvalidCipherTextIOException = org.bouncycastle.crypto.io.InvalidCipherTextIOException;
	using AEADBlockCipher = org.bouncycastle.crypto.modes.AEADBlockCipher;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CCMBlockCipher = org.bouncycastle.crypto.modes.CCMBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using CTSBlockCipher = org.bouncycastle.crypto.modes.CTSBlockCipher;
	using EAXBlockCipher = org.bouncycastle.crypto.modes.EAXBlockCipher;
	using NISTCTSBlockCipher = org.bouncycastle.crypto.modes.NISTCTSBlockCipher;
	using OCBBlockCipher = org.bouncycastle.crypto.modes.OCBBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using SICBlockCipher = org.bouncycastle.crypto.modes.SICBlockCipher;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CipherStreamTest : SimpleTest
	{
		private int streamSize;

		public override string getName()
		{
			return "CipherStreamTest";
		}

		private void testMode(object cipher, CipherParameters @params)
		{
			testWriteRead(cipher, @params, false);
			testWriteRead(cipher, @params, true);
			testReadWrite(cipher, @params, false);
			testReadWrite(cipher, @params, true);

			if (!(cipher is CTSBlockCipher || cipher is NISTCTSBlockCipher))
			{
				testWriteReadEmpty(cipher, @params, false);
				testWriteReadEmpty(cipher, @params, true);
			}

			if (cipher is AEADBlockCipher)
			{
				testTamperedRead((AEADBlockCipher)cipher, @params);
				testTruncatedRead((AEADBlockCipher)cipher, @params);
				testTamperedWrite((AEADBlockCipher)cipher, @params);
			}
		}

		private OutputStream createCipherOutputStream(OutputStream output, object cipher)
		{
			if (cipher is BufferedBlockCipher)
			{
				return new CipherOutputStream(output, (BufferedBlockCipher)cipher);
			}
			else if (cipher is AEADBlockCipher)
			{
				return new CipherOutputStream(output, (AEADBlockCipher)cipher);
			}
			else
			{
				return new CipherOutputStream(output, (StreamCipher)cipher);
			}
		}

		private InputStream createCipherInputStream(byte[] data, object cipher)
		{
			ByteArrayInputStream input = new ByteArrayInputStream(data);
			if (cipher is BufferedBlockCipher)
			{
				return new CipherInputStream(input, (BufferedBlockCipher)cipher);
			}
			else if (cipher is AEADBlockCipher)
			{
				return new CipherInputStream(input, (AEADBlockCipher)cipher);
			}
			else
			{
				return new CipherInputStream(input, (StreamCipher)cipher);
			}
		}

		/// <summary>
		/// Test tampering of ciphertext followed by read from decrypting CipherInputStream
		/// </summary>
		private void testTamperedRead(AEADBlockCipher cipher, CipherParameters @params)
		{
			cipher.init(true, @params);

			byte[] ciphertext = new byte[cipher.getOutputSize(streamSize)];
			cipher.doFinal(ciphertext, cipher.processBytes(new byte[streamSize], 0, streamSize, ciphertext, 0));

			// Tamper
			ciphertext[0] += 1;

			cipher.init(false, @params);
			InputStream input = createCipherInputStream(ciphertext, cipher);
			try
			{
				while (input.read() >= 0)
				{
				}
				fail("Expected invalid ciphertext after tamper and read : " + cipher.getAlgorithmName());
			}
			catch (InvalidCipherTextIOException)
			{
				// Expected
			}
			try
			{
				input.close();
			}
			catch (Exception)
			{
				fail("Unexpected exception after tamper and read : " + cipher.getAlgorithmName());
			}
		}

		/// <summary>
		/// Test truncation of ciphertext to make tag calculation impossible, followed by read from
		/// decrypting CipherInputStream
		/// </summary>
		private void testTruncatedRead(AEADBlockCipher cipher, CipherParameters @params)
		{
			cipher.init(true, @params);

			byte[] ciphertext = new byte[cipher.getOutputSize(streamSize)];
			cipher.doFinal(ciphertext, cipher.processBytes(new byte[streamSize], 0, streamSize, ciphertext, 0));

			// Truncate to just smaller than complete tag
			byte[] truncated = new byte[ciphertext.Length - streamSize - 1];
			JavaSystem.arraycopy(ciphertext, 0, truncated, 0, truncated.Length);

			cipher.init(false, @params);
			InputStream input = createCipherInputStream(truncated, cipher);
			while (true)
			{
				int read = 0;
				try
				{
					read = input.read();
				}
				catch (InvalidCipherTextIOException)
				{
					// Expected
					break;
				}
				catch (Exception)
				{
					fail("Unexpected exception  on truncated read : " + cipher.getAlgorithmName());
					break;
				}
				if (read < 0)
				{
					fail("Expected invalid ciphertext after truncate and read : " + cipher.getAlgorithmName());
					break;
				}
			}
			try
			{
				input.close();
			}
			catch (Exception)
			{
				fail("Unexpected exception after truncate and read : " + cipher.getAlgorithmName());
			}
		}

		/// <summary>
		/// Test tampering of ciphertext followed by write to decrypting CipherOutputStream
		/// </summary>
		private void testTamperedWrite(AEADBlockCipher cipher, CipherParameters @params)
		{
			cipher.init(true, @params);

			byte[] ciphertext = new byte[cipher.getOutputSize(streamSize)];
			cipher.doFinal(ciphertext, cipher.processBytes(new byte[streamSize], 0, streamSize, ciphertext, 0));

			// Tamper
			ciphertext[0] += 1;

			cipher.init(false, @params);
			ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
			OutputStream output = createCipherOutputStream(plaintext, cipher);

			for (int i = 0; i < ciphertext.Length; i++)
			{
				output.write(ciphertext[i]);
			}
			try
			{
				output.close();
				fail("Expected invalid ciphertext after tamper and write : " + cipher.getAlgorithmName());
			}
			catch (InvalidCipherTextIOException)
			{
				// Expected
			}
		}

		/// <summary>
		/// Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
		/// </summary>
		private void testWriteRead(object cipher, CipherParameters @params, bool blocks)
		{
			byte[] data = new byte[streamSize];
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = (byte)(i % 255);
			}

			testWriteRead(cipher, @params, blocks, data);
		}

		/// <summary>
		/// Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
		/// </summary>
		private void testWriteReadEmpty(object cipher, CipherParameters @params, bool blocks)
		{
			byte[] data = new byte[0];

			testWriteRead(cipher, @params, blocks, data);
		}

		private void testWriteRead(object cipher, CipherParameters @params, bool blocks, byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				init(cipher, true, @params);

				OutputStream cOut = createCipherOutputStream(bOut, cipher);
				if (blocks)
				{
					int chunkSize = Math.Max(1, data.Length / 8);
					for (int i = 0; i < data.Length; i += chunkSize)
					{
						cOut.write(data, i, Math.Min(chunkSize, data.Length - i));
					}
				}
				else
				{
					for (int i = 0; i < data.Length; i++)
					{
						cOut.write(data[i]);
					}
				}
				cOut.close();

				byte[] cipherText = bOut.toByteArray();
				bOut.reset();
				init(cipher, false, @params);
				InputStream cIn = createCipherInputStream(cipherText, cipher);

				if (blocks)
				{
					byte[] block = new byte[getBlockSize(cipher) + 1];
					int c;
					while ((c = cIn.read(block)) >= 0)
					{
						bOut.write(block, 0, c);
					}
				}
				else
				{
					int c;
					while ((c = cIn.read()) >= 0)
					{
						bOut.write(c);
					}

				}
				cIn.close();

			}
			catch (Exception e)
			{
				fail("Unexpected exception " + getName(cipher), e);
			}

			byte[] decrypted = bOut.toByteArray();
			if (!Arrays.areEqual(data, decrypted))
			{
				fail("Failed - decrypted data doesn't match: " + getName(cipher));
			}
		}

		private string getName(object cipher)
		{
			if (cipher is BufferedBlockCipher)
			{
				return ((BufferedBlockCipher)cipher).getUnderlyingCipher().getAlgorithmName();
			}
			else if (cipher is AEADBlockCipher)
			{
				return ((AEADBlockCipher)cipher).getUnderlyingCipher().getAlgorithmName();
			}
			else if (cipher is StreamCipher)
			{
				return ((StreamCipher)cipher).getAlgorithmName();
			}
			return null;
		}

		private int getBlockSize(object cipher)
		{
			if (cipher is BlockCipher)
			{
				return ((BlockCipher)cipher).getBlockSize();
			}
			else if (cipher is BufferedBlockCipher)
			{
				return ((BufferedBlockCipher)cipher).getBlockSize();
			}
			else if (cipher is AEADBlockCipher)
			{
				return ((AEADBlockCipher)cipher).getUnderlyingCipher().getBlockSize();
			}
			else if (cipher is StreamCipher)
			{
				return 1;
			}
			return 0;
		}

		private void init(object cipher, bool forEncrypt, CipherParameters @params)
		{
			if (cipher is BufferedBlockCipher)
			{
				((BufferedBlockCipher)cipher).init(forEncrypt, @params);
			}
			else if (cipher is AEADBlockCipher)
			{
				((AEADBlockCipher)cipher).init(forEncrypt, @params);
			}
			else if (cipher is StreamCipher)
			{
				((StreamCipher)cipher).init(forEncrypt, @params);
			}
		}

		public virtual void fail(string message, bool authenticated, bool bc)
		{
			if (bc || !authenticated)
			{
				base.fail(message);
			}
			else
			{
				// javax.crypto.CipherInputStream/CipherOutputStream
				// are broken wrt handling AEAD failures
				JavaSystem.err.println("Broken JCE Streams: " + message);
			}
		}

		/// <summary>
		/// Test CipherInputStream in ENCRYPT_MODE, CipherOutputStream in DECRYPT_MODE
		/// </summary>
		private void testReadWrite(object cipher, CipherParameters @params, bool blocks)
		{
			string lCode = "ABCDEFGHIJKLMNOPQRSTU";

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				init(cipher, true, @params);

				InputStream cIn = createCipherInputStream(lCode.GetBytes(), cipher);
				ByteArrayOutputStream ct = new ByteArrayOutputStream();

				if (blocks)
				{
					byte[] block = new byte[getBlockSize(cipher) + 1];
					int c;
					while ((c = cIn.read(block)) >= 0)
					{
						ct.write(block, 0, c);
					}
				}
				else
				{
					int c;
					while ((c = cIn.read()) >= 0)
					{
						ct.write(c);
					}
				}
				cIn.close();

				init(cipher, false, @params);
				ByteArrayInputStream dataIn = new ByteArrayInputStream(ct.toByteArray());
				OutputStream cOut = createCipherOutputStream(bOut, cipher);

				if (blocks)
				{
					byte[] block = new byte[getBlockSize(cipher) + 1];
					int c;
					while ((c = dataIn.read(block)) >= 0)
					{
						cOut.write(block, 0, c);
					}
				}
				else
				{
					int c;
					while ((c = dataIn.read()) >= 0)
					{
						cOut.write(c);
					}
				}
				cOut.flush();
				cOut.close();

			}
			catch (Exception e)
			{
				fail("Unexpected exception " + getName(cipher), e);
			}

			string res = StringHelper.NewString(bOut.toByteArray());
			if (!res.Equals(lCode))
			{
				fail("Failed read/write - decrypted data doesn't match: " + getName(cipher), lCode, res);
			}
		}

		public override void performTest()
		{
			int[] testSizes = new int[]{0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097};
			for (int i = 0; i < testSizes.Length; i++)
			{
				this.streamSize = testSizes[i];
				performTests();
			}
		}

		private void performTests()
		{
			testModes(new BlowfishEngine(), new BlowfishEngine(), 16);
			testModes(new DESEngine(), new DESEngine(), 8);
			testModes(new DESedeEngine(), new DESedeEngine(), 24);
			testModes(new TEAEngine(), new TEAEngine(), 16);
			testModes(new CAST5Engine(), new CAST5Engine(), 16);
			testModes(new RC2Engine(), new RC2Engine(), 16);
			testModes(new XTEAEngine(), new XTEAEngine(), 16);

			testModes(new AESEngine(), new AESEngine(), 16);
			testModes(new NoekeonEngine(), new NoekeonEngine(), 16);
			testModes(new TwofishEngine(), new TwofishEngine(), 16);
			testModes(new CAST6Engine(), new CAST6Engine(), 16);
			testModes(new SEEDEngine(), new SEEDEngine(), 16);
			testModes(new SerpentEngine(), new SerpentEngine(), 16);
			testModes(new RC6Engine(), new RC6Engine(), 16);
			testModes(new CamelliaEngine(), new CamelliaEngine(), 16);
			testModes(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), 64);

			testMode(new RC4Engine(), new KeyParameter(new byte[16]));
			testMode(new Salsa20Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
			testMode(new XSalsa20Engine(), new ParametersWithIV(new KeyParameter(new byte[32]), new byte[24]));
			testMode(new ChaChaEngine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
			testMode(new Grainv1Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
			testMode(new Grain128Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
			testMode(new HC128Engine(), new KeyParameter(new byte[16]));
			testMode(new HC256Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

			testSkipping(new Salsa20Engine(), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
			testSkipping(new SICBlockCipher(new AESEngine()), new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
		}

		private void testModes(BlockCipher cipher1, BlockCipher cipher2, int keySize)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KeyParameter key = new org.bouncycastle.crypto.params.KeyParameter(new byte[keySize]);
			KeyParameter key = new KeyParameter(new byte[keySize]);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int blockSize = getBlockSize(cipher1);
			int blockSize = getBlockSize(cipher1);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.CipherParameters withIv = new org.bouncycastle.crypto.params.ParametersWithIV(key, new byte[blockSize]);
			CipherParameters withIv = new ParametersWithIV(key, new byte[blockSize]);

			if (blockSize > 1)
			{
				testMode(new PaddedBufferedBlockCipher(cipher1, new PKCS7Padding()), key);

				testMode(new PaddedBufferedBlockCipher(new CBCBlockCipher(cipher1), new PKCS7Padding()), withIv);

				testMode(new BufferedBlockCipher(new OFBBlockCipher(cipher1, blockSize)), withIv);
				testMode(new BufferedBlockCipher(new CFBBlockCipher(cipher1, blockSize)), withIv);
				testMode(new BufferedBlockCipher(new SICBlockCipher(cipher1)), withIv);
			}
			// CTS requires at least one block
			if (blockSize <= 16 && streamSize >= blockSize)
			{
				testMode(new CTSBlockCipher(cipher1), key);
			}
			if (blockSize <= 16 && streamSize >= blockSize)
			{
				testMode(new NISTCTSBlockCipher(NISTCTSBlockCipher.CS1, cipher1), key);
				testMode(new NISTCTSBlockCipher(NISTCTSBlockCipher.CS2, cipher1), key);
				testMode(new NISTCTSBlockCipher(NISTCTSBlockCipher.CS3, cipher1), key);
			}
			if (blockSize == 8 || blockSize == 16)
			{
				testMode(new EAXBlockCipher(cipher1), withIv);
			}
			if (blockSize == 16)
			{
				testMode(new CCMBlockCipher(cipher1), new ParametersWithIV(key, new byte[7]));
				// TODO: need to have a GCM safe version of testMode.
	//            testMode(new GCMBlockCipher(cipher1), withIv);
				testMode(new OCBBlockCipher(cipher1, cipher2), new ParametersWithIV(key, new byte[15]));
			}
		}

		private void testSkipping(StreamCipher cipher, CipherParameters @params)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			init(cipher, true, @params);

			OutputStream cOut = createCipherOutputStream(bOut, cipher);
			byte[] data = new byte[5000];

			(new SecureRandom()).nextBytes(data);

			cOut.write(data);

			cOut.close();

			init(cipher, false, @params);

			InputStream cIn = createCipherInputStream(bOut.toByteArray(), cipher);

			long skip = cIn.skip(50);
			if (skip != 50)
			{
				fail("wrong number of bytes skipped: " + skip);
			}

			byte[] block = new byte[50];

			cIn.read(block);

			if (!areEqual(data, 50, block, 0))
			{
				fail("initial skip mismatch");
			}

			skip = cIn.skip(3000);
			if (skip != 3000)
			{
				fail("wrong number of bytes skipped: " + skip);
			}

			cIn.read(block);

			if (!areEqual(data, 3100, block, 0))
			{
				fail("second skip mismatch");
			}

			cipher.reset();

			cIn = createCipherInputStream(bOut.toByteArray(), cipher);
			if (!cIn.markSupported())
			{
				fail("marking not supported");
			}

			cIn.mark(100);

			cIn.read(block);

			if (!areEqual(data, 0, block, 0))
			{
				fail("initial mark read failed");
			}

			cIn.reset();

			cIn.read(block);

			if (!areEqual(data, 0, block, 0))
			{
				fail(cipher.getAlgorithmName() + " initial reset read failed");
			}

			cIn.reset();

			cIn.read(block);

			cIn.mark(100);

			cIn.read(block);

			if (!areEqual(data, 50, block, 0))
			{
				fail("second mark read failed");
			}

			cIn.reset();

			cIn.read(block);

			if (!areEqual(data, 50, block, 0))
			{
				fail(cipher.getAlgorithmName() + " second reset read failed");
			}

			cIn.mark(3000);

			skip = cIn.skip(2050);
			if (skip != 2050)
			{
				fail("wrong number of bytes skipped: " + skip);
			}

			cIn.reset();

			cIn.read(block);

			if (!areEqual(data, 100, block, 0))
			{
				fail(cipher.getAlgorithmName() + " third reset read failed");
			}

			cIn.read(new byte[2150]);

			cIn.reset();

			cIn.read(block);

			if (!areEqual(data, 100, block, 0))
			{
				fail(cipher.getAlgorithmName() + " fourth reset read failed");
			}

			cIn.close();
		}

		private bool areEqual(byte[] a, int aOff, byte[] b, int bOff)
		{
			for (int i = bOff; i != b.Length; i++)
			{
				if (a[aOff + i - bOff] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static void Main(string[] args)
		{
			runTest(new CipherStreamTest());
		}

	}

}