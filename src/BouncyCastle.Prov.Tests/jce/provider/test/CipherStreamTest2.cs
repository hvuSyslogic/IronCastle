using javax.crypto;

using System;

namespace org.bouncycastle.jce.provider.test
{


	using InvalidCipherTextIOException = org.bouncycastle.crypto.io.InvalidCipherTextIOException;
	using CipherInputStream = org.bouncycastle.jcajce.io.CipherInputStream;
	using CipherOutputStream = org.bouncycastle.jcajce.io.CipherOutputStream;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CipherStreamTest2 : SimpleTest
	{
		private int streamSize;

		public override string getName()
		{
			return "CipherStreamTest2";
		}

		private void testModes(string algo, string[] transforms, bool authenticated)
		{
			Key key = generateKey(algo);
			for (int i = 0; i != transforms.Length; i++)
			{
				string transform = transforms[i];
				string cipherName = algo + transform;

				bool cts = transform.IndexOf("CTS", StringComparison.Ordinal) > -1;
				if (cts && streamSize < Cipher.getInstance(cipherName, "BC").getBlockSize())
				{
					continue;
				}
				testWriteRead(cipherName, key, authenticated, true, false);
				testWriteRead(cipherName, key, authenticated, true, true);
				testWriteRead(cipherName, key, authenticated, false, false);
				testWriteRead(cipherName, key, authenticated, false, true);
				testReadWrite(cipherName, key, authenticated, true, false);
				testReadWrite(cipherName, key, authenticated, true, true);
				testReadWrite(cipherName, key, authenticated, false, false);
				testReadWrite(cipherName, key, authenticated, false, true);

				if (!cts)
				{
					testWriteReadEmpty(cipherName, key, authenticated, true, false);
					testWriteReadEmpty(cipherName, key, authenticated, true, true);
					testWriteReadEmpty(cipherName, key, authenticated, false, false);
					testWriteReadEmpty(cipherName, key, authenticated, false, true);
				}

				if (authenticated)
				{
					testTamperedRead(cipherName, key, true, true);
					testTamperedRead(cipherName, key, true, false);
					testTruncatedRead(cipherName, key, true, true);
					testTruncatedRead(cipherName, key, true, false);
					testTamperedWrite(cipherName, key, true, true);
					testTamperedWrite(cipherName, key, true, false);
				}
			}
		}

		private InputStream createInputStream(byte[] data, Cipher cipher, bool useBc)
		{
			ByteArrayInputStream bytes = new ByteArrayInputStream(data);
			// cast required for earlier JDK
			return useBc ? (InputStream)new CipherInputStream(bytes, cipher) : (InputStream)new CipherInputStream(bytes, cipher);
		}

		private OutputStream createOutputStream(ByteArrayOutputStream bytes, Cipher cipher, bool useBc)
		{
			// cast required for earlier JDK
			return useBc ? (OutputStream)new CipherOutputStream(bytes, cipher) : (OutputStream)new CipherOutputStream(bytes, cipher);
		}

		/// <summary>
		/// Test tampering of ciphertext followed by read from decrypting CipherInputStream
		/// </summary>
		private void testTamperedRead(string name, Key key, bool authenticated, bool useBc)
		{
			Cipher encrypt = Cipher.getInstance(name, "BC");
			Cipher decrypt = Cipher.getInstance(name, "BC");
			encrypt.init(Cipher.ENCRYPT_MODE, key);
			if (encrypt.getIV() != null)
			{
				decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
			}
			else
			{
				decrypt.init(Cipher.DECRYPT_MODE, key);
			}

			byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

			// Tamper
			ciphertext[0] += 1;

			InputStream input = createInputStream(ciphertext, decrypt, useBc);
			try
			{
				while (input.read() >= 0)
				{
				}
				fail("Expected invalid ciphertext after tamper and read : " + name, authenticated, useBc);
			}
			catch (InvalidCipherTextIOException)
			{
				// Expected
			}
			catch (IOException) //     cause will be AEADBadTagException
			{
				// Expected
			}
			try
			{
				input.close();
			}
			catch (Exception e)
			{
				fail("Unexpected exception : " + name, e, authenticated, useBc);
			}
		}

		/// <summary>
		/// Test truncation of ciphertext to make tag calculation impossible, followed by read from
		/// decrypting CipherInputStream
		/// </summary>
		private void testTruncatedRead(string name, Key key, bool authenticated, bool useBc)
		{
			Cipher encrypt = Cipher.getInstance(name, "BC");
			Cipher decrypt = Cipher.getInstance(name, "BC");
			encrypt.init(Cipher.ENCRYPT_MODE, key);
			if (encrypt.getIV() != null)
			{
				decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
			}
			else
			{
				decrypt.init(Cipher.DECRYPT_MODE, key);
			}

			byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

			// Truncate to just smaller than complete tag
			byte[] truncated = new byte[ciphertext.Length - streamSize - 1];
			JavaSystem.arraycopy(ciphertext, 0, truncated, 0, truncated.Length);

			// Tamper
			ciphertext[0] += 1;

			InputStream input = createInputStream(truncated, decrypt, useBc);
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
				catch (IOException)
				{
					// Expected from JDK 1.7 on
					break;
				}
				catch (Exception e)
				{
					fail("Unexpected exception : " + name, e, authenticated, useBc);
					break;
				}
				if (read < 0)
				{
					fail("Expected invalid ciphertext after truncate and read : " + name, authenticated, useBc);
					break;
				}
			}
			try
			{
				input.close();
			}
			catch (Exception e)
			{
				fail("Unexpected exception : " + name, e, authenticated, useBc);
			}
		}

		/// <summary>
		/// Test tampering of ciphertext followed by write to decrypting CipherOutputStream
		/// </summary>
		private void testTamperedWrite(string name, Key key, bool authenticated, bool useBc)
		{
			Cipher encrypt = Cipher.getInstance(name, "BC");
			Cipher decrypt = Cipher.getInstance(name, "BC");
			encrypt.init(Cipher.ENCRYPT_MODE, key);
			if (encrypt.getIV() != null)
			{
				decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
			}
			else
			{
				decrypt.init(Cipher.DECRYPT_MODE, key);
			}

			byte[] ciphertext = encrypt.doFinal(new byte[streamSize]);

			// Tamper
			ciphertext[0] += 1;

			ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
			OutputStream output = createOutputStream(plaintext, decrypt, useBc);

			for (int i = 0; i < ciphertext.Length; i++)
			{
				output.write(ciphertext[i]);
			}
			try
			{
				output.close();
				fail("Expected invalid ciphertext after tamper and write : " + name, authenticated, useBc);
			}
			catch (InvalidCipherTextIOException)
			{
				// Expected
			}
		}

		/// <summary>
		/// Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
		/// </summary>
		private void testWriteRead(string name, Key key, bool authenticated, bool useBc, bool blocks)
		{
			byte[] data = new byte[streamSize];
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = (byte)(i % 255);
			}

			testWriteRead(name, key, authenticated, useBc, blocks, data);
		}

		/// <summary>
		/// Test CipherOutputStream in ENCRYPT_MODE, CipherInputStream in DECRYPT_MODE
		/// </summary>
		private void testWriteReadEmpty(string name, Key key, bool authenticated, bool useBc, bool blocks)
		{
			byte[] data = new byte[0];

			testWriteRead(name, key, authenticated, useBc, blocks, data);
		}

		private void testWriteRead(string name, Key key, bool authenticated, bool useBc, bool blocks, byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				Cipher encrypt = Cipher.getInstance(name, "BC");
				Cipher decrypt = Cipher.getInstance(name, "BC");
				encrypt.init(Cipher.ENCRYPT_MODE, key);
				if (encrypt.getIV() != null)
				{
					decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encrypt.getIV()));
				}
				else
				{
					decrypt.init(Cipher.DECRYPT_MODE, key);
				}

				OutputStream cOut = createOutputStream(bOut, encrypt, useBc);
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
				InputStream cIn = createInputStream(cipherText, decrypt, useBc);

				if (blocks)
				{
					byte[] block = new byte[encrypt.getBlockSize() + 1];
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
				fail("Unexpected exception " + name, e, authenticated, useBc);
			}

			byte[] decrypted = bOut.toByteArray();
			if (!Arrays.areEqual(data, decrypted))
			{
				fail("Failed - decrypted data doesn't match: " + name, authenticated, useBc);
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
				// JavaSystem.err.println("Broken JCE Streams: " + message);
			}
		}

		public virtual void fail(string message, Exception throwable, bool authenticated, bool bc)
		{
			if (bc || !authenticated)
			{
				base.fail(message, throwable);
			}
			else
			{
				// javax.crypto.CipherInputStream/CipherOutputStream
				// are broken wrt handling AEAD failures
				//JavaSystem.err.println("Broken JCE Streams: " + message + " : " + throwable);
				Console.WriteLine(throwable.ToString());
				Console.Write(throwable.StackTrace);
			}
		}

		/// <summary>
		/// Test CipherInputStream in ENCRYPT_MODE, CipherOutputStream in DECRYPT_MODE
		/// </summary>
		private void testReadWrite(string name, Key key, bool authenticated, bool useBc, bool blocks)
		{
			string lCode = "ABCDEFGHIJKLMNOPQRSTU";

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				Cipher @in = Cipher.getInstance(name, "BC");
				Cipher @out = Cipher.getInstance(name, "BC");
				@in.init(Cipher.ENCRYPT_MODE, key);
				if (@in.getIV() != null)
				{
					@out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(@in.getIV()));
				}
				else
				{
					@out.init(Cipher.DECRYPT_MODE, key);
				}

				InputStream cIn = createInputStream(lCode.GetBytes(), @in, useBc);
				OutputStream cOut = createOutputStream(bOut, @out, useBc);

				if (blocks)
				{
					byte[] block = new byte[@in.getBlockSize() + 1];
					int c;
					while ((c = cIn.read(block)) >= 0)
					{
						cOut.write(block, 0, c);
					}
				}
				else
				{
					int c;
					while ((c = cIn.read()) >= 0)
					{
						cOut.write(c);
					}
				}

				cIn.close();

				cOut.flush();
				cOut.close();

			}
			catch (Exception e)
			{
				fail("Unexpected exception " + name, e, authenticated, useBc);
			}

			string res = StringHelper.NewString(bOut.toByteArray());
			if (!res.Equals(lCode))
			{
				fail("Failed - decrypted data doesn't match: " + name, authenticated, useBc);
			}
		}

		private static Key generateKey(string name)
		{
			KeyGenerator kGen;

			if (name.IndexOf('/') < 0)
			{
				kGen = KeyGenerator.getInstance(name, "BC");
			}
			else
			{
				kGen = KeyGenerator.getInstance(name.Substring(0, name.IndexOf('/')), "BC");
			}
			return kGen.generateKey();
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
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String[] blockCiphers64 = new String[]{"BLOWFISH", "DES", "DESEDE", "TEA", "CAST5", "RC2", "XTEA"};
			string[] blockCiphers64 = new string[]{"BLOWFISH", "DES", "DESEDE", "TEA", "CAST5", "RC2", "XTEA"};

			for (int i = 0; i != blockCiphers64.Length; i++)
			{
				testModes(blockCiphers64[i], new string[]{"/ECB/PKCS5Padding", "/CBC/PKCS5Padding", "/OFB/NoPadding", "/CFB/NoPadding", "/CTS/NoPadding"}, false);
				testModes(blockCiphers64[i], new string[]{"/EAX/NoPadding"}, true);
			}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String[] blockCiphers128 = new String[]{ "AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Serpent", "RC6", "CAMELLIA"};
			string[] blockCiphers128 = new string[]{"AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Serpent", "RC6", "CAMELLIA"};

			for (int i = 0; i != blockCiphers128.Length; i++)
			{
				testModes(blockCiphers128[i], new string[]{"/ECB/PKCS5Padding", "/CBC/PKCS5Padding", "/OFB/NoPadding", "/CFB/NoPadding", "/CTS/NoPadding", "/CTR/NoPadding", "/SIC/NoPadding"}, false);
				testModes(blockCiphers128[i], new string[]{"/CCM/NoPadding", "/EAX/NoPadding", "/GCM/NoPadding", "/OCB/NoPadding"}, true);
			}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String[] streamCiphers = new String[]{ "ARC4", "SALSA20", "XSalsa20", "ChaCha", "ChaCha7539", "Grainv1", "Grain128", "HC128", "HC256"};
			string[] streamCiphers = new string[]{"ARC4", "SALSA20", "XSalsa20", "ChaCha", "ChaCha7539", "Grainv1", "Grain128", "HC128", "HC256"};

			for (int i = 0; i != streamCiphers.Length; i++)
			{
				testModes(streamCiphers[i], new string[]{""}, false);
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());
			runTest(new CipherStreamTest2());
		}

	}

}