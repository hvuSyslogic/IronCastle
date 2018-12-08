using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// An implementation of the AES Key Wrap with Padding specification
	/// as described in RFC 5649.
	/// <para>
	/// For details on the specification see:
	/// <a href="https://tools.ietf.org/html/rfc5649">https://tools.ietf.org/html/rfc5649</a>
	/// </para>
	/// </summary>
	public class RFC5649WrapEngine : Wrapper
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			preIV = highOrderIV;
		}

		private BlockCipher engine;
		private KeyParameter param;
		private bool forWrapping;

		// The AIV as defined in the RFC
		private byte[] highOrderIV = new byte[] {unchecked((byte)0xa6), (byte)0x59, (byte)0x59, unchecked((byte)0xa6)};
		private byte[] preIV;

		private byte[] extractedAIV = null;

		public RFC5649WrapEngine(BlockCipher engine)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.engine = engine;
		}

		public virtual void init(bool forWrapping, CipherParameters param)
		{
			this.forWrapping = forWrapping;

			if (param is ParametersWithRandom)
			{
				param = ((ParametersWithRandom)param).getParameters();
			}

			if (param is KeyParameter)
			{
				this.param = (KeyParameter)param;
				this.preIV = highOrderIV;
			}
			else if (param is ParametersWithIV)
			{
				this.preIV = ((ParametersWithIV)param).getIV();
				this.param = (KeyParameter)((ParametersWithIV)param).getParameters();
				if (this.preIV.Length != 4)
				{
					throw new IllegalArgumentException("IV length not equal to 4");
				}
			}
		}

		public virtual string getAlgorithmName()
		{
			return engine.getAlgorithmName();
		}

		/// <summary>
		/// Pads the plaintext (i.e., the key to be wrapped)
		/// as per section 4.1 of RFC 5649.
		/// </summary>
		/// <param name="plaintext"> The key being wrapped. </param>
		/// <returns> The padded key. </returns>
		private byte[] padPlaintext(byte[] plaintext)
		{
			int plaintextLength = plaintext.Length;
			int numOfZerosToAppend = (8 - (plaintextLength % 8)) % 8;
			byte[] paddedPlaintext = new byte[plaintextLength + numOfZerosToAppend];
			JavaSystem.arraycopy(plaintext, 0, paddedPlaintext, 0, plaintextLength);
			if (numOfZerosToAppend != 0)
			{
				// plaintext (i.e., key to be wrapped) does not have
				// a multiple of 8 octet blocks so it must be padded
				byte[] zeros = new byte[numOfZerosToAppend];
				JavaSystem.arraycopy(zeros, 0, paddedPlaintext, plaintextLength, numOfZerosToAppend);
			}
			return paddedPlaintext;
		}

		public virtual byte[] wrap(byte[] @in, int inOff, int inLen)
		{
			if (!forWrapping)
			{
				throw new IllegalStateException("not set for wrapping");
			}
			byte[] iv = new byte[8];

			// MLI = size of key to be wrapped
			byte[] mli = Pack.intToBigEndian(inLen);
			// copy in the fixed portion of the AIV
			JavaSystem.arraycopy(preIV, 0, iv, 0, preIV.Length);
			// copy in the MLI after the AIV
			JavaSystem.arraycopy(mli, 0, iv, preIV.Length, mli.Length);

			// get the relevant plaintext to be wrapped
			byte[] relevantPlaintext = new byte[inLen];
			JavaSystem.arraycopy(@in, inOff, relevantPlaintext, 0, inLen);
			byte[] paddedPlaintext = padPlaintext(relevantPlaintext);

			if (paddedPlaintext.Length == 8)
			{
				// if the padded plaintext contains exactly 8 octets,
				// then prepend iv and encrypt using AES in ECB mode.

				// prepend the IV to the plaintext
				byte[] paddedPlainTextWithIV = new byte[paddedPlaintext.Length + iv.Length];
				JavaSystem.arraycopy(iv, 0, paddedPlainTextWithIV, 0, iv.Length);
				JavaSystem.arraycopy(paddedPlaintext, 0, paddedPlainTextWithIV, iv.Length, paddedPlaintext.Length);

				engine.init(true, param);
				for (int i = 0; i < paddedPlainTextWithIV.Length; i += engine.getBlockSize())
				{
					engine.processBlock(paddedPlainTextWithIV, i, paddedPlainTextWithIV, i);
				}

				return paddedPlainTextWithIV;
			}
			else
			{
				// otherwise, apply the RFC 3394 wrap to
				// the padded plaintext with the new IV
				Wrapper wrapper = new RFC3394WrapEngine(engine);
				ParametersWithIV paramsWithIV = new ParametersWithIV(param, iv);
				wrapper.init(true, paramsWithIV);
				return wrapper.wrap(paddedPlaintext, 0, paddedPlaintext.Length);
			}

		}

		public virtual byte[] unwrap(byte[] @in, int inOff, int inLen)
		{
			if (forWrapping)
			{
				throw new IllegalStateException("not set for unwrapping");
			}

			int n = inLen / 8;

			if ((n * 8) != inLen)
			{
				throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
			}

			if (n == 1)
			{
				throw new InvalidCipherTextException("unwrap data must be at least 16 bytes");
			}

			byte[] relevantCiphertext = new byte[inLen];
			JavaSystem.arraycopy(@in, inOff, relevantCiphertext, 0, inLen);
			byte[] decrypted = new byte[inLen];
			byte[] paddedPlaintext;

			if (n == 2)
			{
				// When there are exactly two 64-bit blocks of ciphertext,
				// they are decrypted as a single block using AES in ECB.
				engine.init(false, param);
				for (int i = 0; i < relevantCiphertext.Length; i += engine.getBlockSize())
				{
					engine.processBlock(relevantCiphertext, i, decrypted, i);
				}

				// extract the AIV
				extractedAIV = new byte[8];
				JavaSystem.arraycopy(decrypted, 0, extractedAIV, 0, extractedAIV.Length);
				paddedPlaintext = new byte[decrypted.Length - extractedAIV.Length];
				JavaSystem.arraycopy(decrypted, extractedAIV.Length, paddedPlaintext, 0, paddedPlaintext.Length);
			}
			else
			{
				// Otherwise, unwrap as per RFC 3394 but don't check IV the same way
				decrypted = rfc3394UnwrapNoIvCheck(@in, inOff, inLen);
				paddedPlaintext = decrypted;
			}

			// Decompose the extracted AIV to the fixed portion and the MLI
			byte[] extractedHighOrderAIV = new byte[4];
			byte[] mliBytes = new byte[4];
			JavaSystem.arraycopy(extractedAIV, 0, extractedHighOrderAIV, 0, extractedHighOrderAIV.Length);
			JavaSystem.arraycopy(extractedAIV, extractedHighOrderAIV.Length, mliBytes, 0, mliBytes.Length);
			int mli = Pack.bigEndianToInt(mliBytes, 0);
			// Even if a check fails we still continue and check everything 
			// else in order to avoid certain timing based side-channel attacks.
			bool isValid = true;

			// Check the fixed portion of the AIV
			if (!Arrays.constantTimeAreEqual(extractedHighOrderAIV, preIV))
			{
				isValid = false;
			}

			// Check the MLI against the actual length
			int upperBound = paddedPlaintext.Length;
			int lowerBound = upperBound - 8;
			if (mli <= lowerBound)
			{
				isValid = false;
			}
			if (mli > upperBound)
			{
				isValid = false;
			}

			// Check the number of padded zeros
			int expectedZeros = upperBound - mli;
			if (expectedZeros >= paddedPlaintext.Length)
			{
				isValid = false;
				expectedZeros = paddedPlaintext.Length;
			}

			byte[] zeros = new byte[expectedZeros];
			byte[] pad = new byte[expectedZeros];
			JavaSystem.arraycopy(paddedPlaintext, paddedPlaintext.Length - expectedZeros, pad, 0, expectedZeros);
			if (!Arrays.constantTimeAreEqual(pad, zeros))
			{
				isValid = false;
			}

			if (!isValid)
			{
				throw new InvalidCipherTextException("checksum failed");
			}

			// Extract the plaintext from the padded plaintext
			byte[] plaintext = new byte[mli];
			JavaSystem.arraycopy(paddedPlaintext, 0, plaintext, 0, plaintext.Length);

			return plaintext;
		}

		/// <summary>
		/// Performs steps 1 and 2 of the unwrap process defined in RFC 3394.
		/// This code is duplicated from RFC3394WrapEngine because that class
		/// will throw an error during unwrap because the IV won't match up.
		/// </summary>
		/// <param name="in"> </param>
		/// <param name="inOff"> </param>
		/// <param name="inLen"> </param>
		/// <returns> Unwrapped data. </returns>
		private byte[] rfc3394UnwrapNoIvCheck(byte[] @in, int inOff, int inLen)
		{
			byte[] iv = new byte[8];
			byte[] block = new byte[inLen - iv.Length];
			byte[] a = new byte[iv.Length];
			byte[] buf = new byte[8 + iv.Length];

			JavaSystem.arraycopy(@in, inOff, a, 0, iv.Length);
			JavaSystem.arraycopy(@in, inOff + iv.Length, block, 0, inLen - iv.Length);

			engine.init(false, param);

			int n = inLen / 8;
			n = n - 1;

			for (int j = 5; j >= 0; j--)
			{
				for (int i = n; i >= 1; i--)
				{
					JavaSystem.arraycopy(a, 0, buf, 0, iv.Length);
					JavaSystem.arraycopy(block, 8 * (i - 1), buf, iv.Length, 8);

					int t = n * j + i;
					for (int k = 1; t != 0; k++)
					{
						byte v = (byte)t;

						buf[iv.Length - k] ^= v;

						t = (int)((uint)t >> 8);
					}

					engine.processBlock(buf, 0, buf, 0);
					JavaSystem.arraycopy(buf, 0, a, 0, 8);
					JavaSystem.arraycopy(buf, 8, block, 8 * (i - 1), 8);
				}
			}

			// set the extracted AIV
			extractedAIV = a;

			return block;
		}

	}

}