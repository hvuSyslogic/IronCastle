namespace org.bouncycastle.crypto.test
{
	using AEADBlockCipher = org.bouncycastle.crypto.modes.AEADBlockCipher;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public class AEADTestUtil
	{
		public static void testTampering(Test test, AEADBlockCipher cipher, CipherParameters @params)
		{
			byte[] plaintext = new byte[1000];
			for (int i = 0; i < plaintext.Length; i++)
			{
				plaintext[i] = (byte)i;
			}
			cipher.init(true, @params);

			byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.Length)];
			int len = cipher.processBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
			cipher.doFinal(ciphertext, len);

			int macLength = cipher.getMac().Length;

			// Test tampering with a single byte
			cipher.init(false, @params);
			byte[] tampered = new byte[ciphertext.Length];
			byte[] output = new byte[plaintext.Length];
			JavaSystem.arraycopy(ciphertext, 0, tampered, 0, tampered.Length);
			tampered[0] += 1;

			cipher.processBytes(tampered, 0, tampered.Length, output, 0);
			try
			{
				cipher.doFinal(output, 0);
				throw new TestFailedException(new SimpleTestResult(false, test + " : tampering of ciphertext not detected."));
			}
			catch (InvalidCipherTextException)
			{
				// Expected
			}

			// Test truncation of ciphertext to < tag length
			cipher.init(false, @params);
			byte[] truncated = new byte[macLength - 1];
			JavaSystem.arraycopy(ciphertext, 0, truncated, 0, truncated.Length);

			cipher.processBytes(truncated, 0, truncated.Length, output, 0);
			try
			{
				cipher.doFinal(output, 0);
				fail(test, "tampering of ciphertext not detected.");
			}
			catch (InvalidCipherTextException)
			{
				// Expected
			}
		}

		private static void fail(Test test, string message)
		{
			throw new TestFailedException(SimpleTestResult.failed(test, message));
		}

		private static void fail(Test test, string message, string expected, string result)
		{
			throw new TestFailedException(SimpleTestResult.failed(test, message, expected, result));
		}

		public static void testReset(Test test, AEADBlockCipher cipher1, AEADBlockCipher cipher2, CipherParameters @params)
		{
			cipher1.init(true, @params);

			byte[] plaintext = new byte[1000];
			byte[] ciphertext = new byte[cipher1.getOutputSize(plaintext.Length)];

			// Establish baseline answer
			crypt(cipher1, plaintext, ciphertext);

			// Test encryption resets
			checkReset(test, cipher1, @params, true, plaintext, ciphertext);

			// Test decryption resets with fresh instance
			cipher2.init(false, @params);
			checkReset(test, cipher2, @params, false, ciphertext, plaintext);
		}

		private static void checkReset(Test test, AEADBlockCipher cipher, CipherParameters @params, bool encrypt, byte[] pretext, byte[] posttext)
		{
			// Do initial run
			byte[] output = new byte[posttext.Length];
			crypt(cipher, pretext, output);

			// Check encrypt resets cipher
			crypt(cipher, pretext, output);
			if (!Arrays.areEqual(output, posttext))
			{
				fail(test, (encrypt ? "Encrypt" : "Decrypt") + " did not reset cipher.");
			}

			// Check init resets data
			cipher.processBytes(pretext, 0, 100, output, 0);
			cipher.init(encrypt, @params);

			try
			{
				crypt(cipher, pretext, output);
			}
			catch (DataLengthException)
			{
				fail(test, "Init did not reset data.");
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(test, "Init did not reset data.", StringHelper.NewString(Hex.encode(posttext)), StringHelper.NewString(Hex.encode(output)));
			}

			// Check init resets AD
			cipher.processAADBytes(pretext, 0, 100);
			cipher.init(encrypt, @params);

			try
			{
				crypt(cipher, pretext, output);
			}
			catch (DataLengthException)
			{
				fail(test, "Init did not reset additional data.");
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(test, "Init did not reset additional data.");
			}

			// Check reset resets data
			cipher.processBytes(pretext, 0, 100, output, 0);
			cipher.reset();

			try
			{
				crypt(cipher, pretext, output);
			}
			catch (DataLengthException)
			{
				fail(test, "Init did not reset data.");
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(test, "Reset did not reset data.");
			}

			// Check reset resets AD
			cipher.processAADBytes(pretext, 0, 100);
			cipher.reset();

			try
			{
				crypt(cipher, pretext, output);
			}
			catch (DataLengthException)
			{
				fail(test, "Init did not reset data.");
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(test, "Reset did not reset additional data.");
			}
		}

		private static void crypt(AEADBlockCipher cipher, byte[] plaintext, byte[] output)
		{
			int len = cipher.processBytes(plaintext, 0, plaintext.Length, output, 0);
			cipher.doFinal(output, len);
		}

		public static void testOutputSizes(Test test, AEADBlockCipher cipher, AEADParameters @params)
		{
			int maxPlaintext = cipher.getUnderlyingCipher().getBlockSize() * 10;
			byte[] plaintext = new byte[maxPlaintext];
			byte[] ciphertext = new byte[maxPlaintext * 2];

			// Check output size calculations for truncated ciphertext lengths
			cipher.init(true, @params);
			cipher.doFinal(ciphertext, 0);
			int macLength = cipher.getMac().Length;

			cipher.init(false, @params);
			for (int i = 0; i < macLength; i++)
			{
				cipher.reset();
				if (cipher.getUpdateOutputSize(i) != 0)
				{
					fail(test, "AE cipher should not produce update output with ciphertext length <= macSize");
				}
				if (cipher.getOutputSize(i) != 0)
				{
					fail(test, "AE cipher should not produce output with ciphertext length <= macSize");
				}
			}

			for (int i = 0; i < plaintext.Length; i++)
			{
				cipher.init(true, @params);
				int expectedCTUpdateSize = cipher.getUpdateOutputSize(i);
				int expectedCTOutputSize = cipher.getOutputSize(i);

				if (expectedCTUpdateSize < 0)
				{
					fail(test, "Encryption update output size should not be < 0 for size " + i);
				}

				if (expectedCTOutputSize < 0)
				{
					fail(test, "Encryption update output size should not be < 0 for size " + i);
				}

				int actualCTSize = cipher.processBytes(plaintext, 0, i, ciphertext, 0);

				if (expectedCTUpdateSize != actualCTSize)
				{
					fail(test, "Encryption update output size did not match calculated for plaintext length " + i, expectedCTUpdateSize.ToString(), actualCTSize.ToString());
				}

				actualCTSize += cipher.doFinal(ciphertext, actualCTSize);

				if (expectedCTOutputSize != actualCTSize)
				{
					fail(test, "Encryption actual final output size did not match calculated for plaintext length " + i, expectedCTOutputSize.ToString(), actualCTSize.ToString());
				}

				cipher.init(false, @params);
				int expectedPTUpdateSize = cipher.getUpdateOutputSize(actualCTSize);
				int expectedPTOutputSize = cipher.getOutputSize(actualCTSize);

				if (expectedPTOutputSize != i)
				{
					fail(test, "Decryption update output size did not original plaintext length " + i, expectedPTUpdateSize.ToString(), i.ToString());
				}

				int actualPTSize = cipher.processBytes(ciphertext, 0, actualCTSize, plaintext, 0);

				if (expectedPTUpdateSize != actualPTSize)
				{
					fail(test, "Decryption update output size did not match calculated for plaintext length " + i, expectedPTUpdateSize.ToString(), actualPTSize.ToString());
				}

				actualPTSize += cipher.doFinal(plaintext, actualPTSize);

				if (expectedPTOutputSize != actualPTSize)
				{
					fail(test, "Decryption update output size did not match calculated for plaintext length " + i, expectedPTOutputSize.ToString(), actualPTSize.ToString());
				}

			}
		}

		public static void testBufferSizeChecks(Test test, AEADBlockCipher cipher, AEADParameters @params)
		{
			int blockSize = cipher.getUnderlyingCipher().getBlockSize();
			int maxPlaintext = (blockSize * 10);
			byte[] plaintext = new byte[maxPlaintext];


			cipher.init(true, @params);

			int expectedUpdateOutputSize = cipher.getUpdateOutputSize(plaintext.Length);
			byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.Length)];

			try
			{
				cipher.processBytes(new byte[maxPlaintext - 1], 0, maxPlaintext, new byte[expectedUpdateOutputSize], 0);
				fail(test, "processBytes should validate input buffer length");
			}
			catch (DataLengthException)
			{
				// Expected
			}
			cipher.reset();

			if (expectedUpdateOutputSize > 0)
			{
				int outputTrigger = 0;
				// Process bytes until output would be produced
				for (int i = 0; i < plaintext.Length; i++)
				{
					if (cipher.getUpdateOutputSize(1) != 0)
					{
						outputTrigger = i + 1;
						break;
					}
					cipher.processByte(plaintext[i], ciphertext, 0);
				}
				if (outputTrigger == 0)
				{
					fail(test, "Failed to find output trigger size");
				}
				try
				{
					cipher.processByte(plaintext[0], new byte[cipher.getUpdateOutputSize(1) - 1], 0);
					fail(test, "Encrypt processByte should validate output buffer length");
				}
				catch (OutputLengthException)
				{
					// Expected
				}
				cipher.reset();

				// Repeat checking with entire input at once
				try
				{
					cipher.processBytes(plaintext, 0, outputTrigger, new byte[cipher.getUpdateOutputSize(outputTrigger) - 1], 0);
					fail(test, "Encrypt processBytes should validate output buffer length");
				}
				catch (OutputLengthException)
				{
					// Expected
				}
				cipher.reset();

			}

			// Remember the actual ciphertext for later
			int actualOutputSize = cipher.processBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
			actualOutputSize += cipher.doFinal(ciphertext, actualOutputSize);
			int macSize = cipher.getMac().Length;

			cipher.reset();
			try
			{
				cipher.processBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
				cipher.doFinal(new byte[cipher.getOutputSize(0) - 1], 0);
				fail(test, "Encrypt doFinal should validate output buffer length");
			}
			catch (OutputLengthException)
			{
				// Expected
			}

			// Decryption tests

			cipher.init(false, @params);
			expectedUpdateOutputSize = cipher.getUpdateOutputSize(actualOutputSize);

			if (expectedUpdateOutputSize > 0)
			{
				// Process bytes until output would be produced
				int outputTrigger = 0;
				for (int i = 0; i < plaintext.Length; i++)
				{
					if (cipher.getUpdateOutputSize(1) != 0)
					{
						outputTrigger = i + 1;
						break;
					}
					cipher.processByte(ciphertext[i], plaintext, 0);
				}
				if (outputTrigger == 0)
				{
					fail(test, "Failed to find output trigger size");
				}

				try
				{
					cipher.processByte(ciphertext[0], new byte[cipher.getUpdateOutputSize(1) - 1], 0);
					fail(test, "Decrypt processByte should validate output buffer length");
				}
				catch (OutputLengthException)
				{
					// Expected
				}
				cipher.reset();

				// Repeat test with processBytes
				try
				{
					cipher.processBytes(ciphertext, 0, outputTrigger, new byte[cipher.getUpdateOutputSize(outputTrigger) - 1], 0);
					fail(test, "Decrypt processBytes should validate output buffer length");
				}
				catch (OutputLengthException)
				{
					// Expected
				}
			}

			cipher.reset();
			// Data less than mac length should fail before output length check
			try
			{
				// Assumes AE cipher on decrypt can't return any data until macSize bytes are received
				if (cipher.processBytes(ciphertext, 0, macSize - 1, plaintext, 0) != 0)
				{
					fail(test, "AE cipher unexpectedly produced output");
				}
				cipher.doFinal(new byte[0], 0);
				fail(test, "Decrypt doFinal should check ciphertext length");
			}
			catch (InvalidCipherTextException)
			{
				// Expected
			}

			try
			{
				// Search through plaintext lengths until one is found that creates >= 1 buffered byte
				// during decryption of ciphertext for doFinal to handle
				for (int i = 2; i < plaintext.Length; i++)
				{
					cipher.init(true, @params);
					int encrypted = cipher.processBytes(plaintext, 0, i, ciphertext, 0);
					encrypted += cipher.doFinal(ciphertext, encrypted);

					cipher.init(false, @params);
					cipher.processBytes(ciphertext, 0, encrypted - 1, plaintext, 0);
					if (cipher.processByte(ciphertext[encrypted - 1], plaintext, 0) == 0)
					{
						cipher.doFinal(new byte[cipher.getOutputSize(0) - 1], 0);
						fail(test, "Decrypt doFinal should check output length");
						cipher.reset();

						// Truncated Mac should be reported in preference to inability to output
						// buffered plaintext byte
						try
						{
							cipher.processBytes(ciphertext, 0, actualOutputSize - 1, plaintext, 0);
							cipher.doFinal(new byte[cipher.getOutputSize(0) - 1], 0);
							fail(test, "Decrypt doFinal should check ciphertext length");
						}
						catch (InvalidCipherTextException)
						{
							// Expected
						}
						cipher.reset();
					}
				}
				fail(test, "Decrypt doFinal test couldn't find a ciphertext length that buffered for doFinal");
			}
			catch (OutputLengthException)
			{
				// Expected
			}
		}

		internal static AEADParameters reuseKey(AEADParameters p)
		{
			return new AEADParameters(null, p.getMacSize(), p.getNonce(), p.getAssociatedText());
		}
	}

}