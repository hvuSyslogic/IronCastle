namespace org.bouncycastle.crypto.test.speedy
{
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// Poly1305 message authentication code, designed by D. J. Bernstein.
	/// <para>
	/// Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
	/// consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
	/// effective key bits) used in the authenticator.
	/// </para>
	/// <para>
	/// This implementation is adapted from the public domain <a href="http://nacl.cr.yp.to/">nacl</a>
	/// <code>ref</code> implementation, and is probably too slow for real usage.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= Poly1305KeyGenerator </seealso>
	public class Poly1305Reference : Mac
	{
		private const int BLOCK_SIZE = 16;
		private static readonly int STATE_SIZE = BLOCK_SIZE + 1;
		private static int[] minusp = new int[] {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

		private readonly BlockCipher cipher;

		/// <summary>
		/// Encrypted nonce </summary>
		private readonly byte[] encryptedNonce = new byte[BLOCK_SIZE];

		/// <summary>
		/// Private integer r *, expanded to 17 bytes </summary>
		private readonly int[] r = new int[STATE_SIZE];

		/// <summary>
		/// Accumulated authenticator value </summary>
		private readonly int[] h = new int[STATE_SIZE];

		/// <summary>
		/// Temp buffer for incorporating into authenticator </summary>
		private readonly int[] c = new int[STATE_SIZE];

		private readonly byte[] singleByte = new byte[1];

		/// <summary>
		/// Current block of buffered input </summary>
		private readonly byte[] currentBlock = new byte[BLOCK_SIZE];

		/// <summary>
		/// Current offset in input buffer </summary>
		private int currentBlockOffset = 0;

		public Poly1305Reference(BlockCipher cipher)
		{
			if (cipher.getBlockSize() != BLOCK_SIZE)
			{
				throw new IllegalArgumentException("Poly1305 requires a 128 bit block cipher.");
			}
			this.cipher = cipher;
		}

		public virtual void init(CipherParameters @params)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] nonce;
			byte[] nonce;
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] key;
			byte[] key;
			if ((@params is ParametersWithIV) && ((ParametersWithIV)@params).getParameters() is KeyParameter)
			{
				nonce = ((ParametersWithIV)@params).getIV();
				key = ((KeyParameter)((ParametersWithIV)@params).getParameters()).getKey();
			}
			else
			{
				throw new IllegalArgumentException("Poly1305 requires a key and and IV.");
			}

			setKey(key, nonce);
			reset();
		}

		private void setKey(byte[] key, byte[] nonce)
		{
			if (nonce.Length != BLOCK_SIZE)
			{
				throw new IllegalArgumentException("Poly1305 requires a 128 bit IV.");
			}
			Poly1305KeyGenerator.checkKey(key);

			// Expand private integer r
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				r[i] = key[BLOCK_SIZE + i] & 0xFF;
			}
			r[BLOCK_SIZE] = 0;

			// Calculate encrypted nonce
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] cipherKey = new byte[BLOCK_SIZE];
			byte[] cipherKey = new byte[BLOCK_SIZE];
			JavaSystem.arraycopy(key, 0, cipherKey, 0, cipherKey.Length);

			cipher.init(true, new KeyParameter(cipherKey));
			cipher.processBlock(nonce, 0, this.encryptedNonce, 0);
		}

		public virtual string getAlgorithmName()
		{
			return "Poly1305-Ref-" + cipher.getAlgorithmName();
		}

		public virtual int getMacSize()
		{
			return BLOCK_SIZE;
		}

		public virtual void update(byte @in)
		{
			singleByte[0] = @in;
			update(singleByte, 0, 1);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			int copied = 0;
			while (len > copied)
			{
				if (currentBlockOffset == currentBlock.Length)
				{
					processBlock();
					currentBlockOffset = 0;
				}

				int toCopy = Math.Min((len - copied), currentBlock.Length - currentBlockOffset);
				JavaSystem.arraycopy(@in, copied + inOff, currentBlock, currentBlockOffset, toCopy);
				copied += toCopy;
				currentBlockOffset += toCopy;
			}

		}

		/// <summary>
		/// Add a full block of 16 bytes of data, padded to 17 bytes, to the MAC
		/// </summary>
		private void processBlock()
		{
			for (int i = 0; i < currentBlockOffset; i++)
			{
				c[i] = currentBlock[i] & 0xFF;
			}
			c[currentBlockOffset] = 1;
			for (int i = currentBlockOffset + 1; i < c.Length; i++)
			{
				c[i] = 0;
			}
			add(h, c);
			mulmod(h, r);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			if (outOff + BLOCK_SIZE > @out.Length)
			{
				throw new OutputLengthException("Output buffer is too short.");
			}

			if (currentBlockOffset > 0)
			{
				// Process padded final block
				processBlock();
			}

			freeze(h);

			// Add encrypted nonce to result
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				c[i] = encryptedNonce[i] & 0xFF;
			}
			c[BLOCK_SIZE] = 0;
			add(h, c);

			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				@out[outOff + i] = (byte)h[i];
			}

			reset();
			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
			currentBlockOffset = 0;
			for (int i = 0; i < h.Length; i++)
			{
				h[i] = 0;
			}
		}

		// 130 bit math adapted from nacl ref implementation

		/// <summary>
		/// 130 bit add with carry.
		/// </summary>
		private static void add(int[] h, int[] c)
		{
			int u = 0;
			for (int j = 0; j < 17; ++j)
			{
				u += h[j] + c[j];
				h[j] = u & 255;
				u >>= 8;
			}
		}

		/// <summary>
		/// 130 bit multiplication mod 2^130-5
		/// </summary>
		private void mulmod(int[] h, int[] r)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int[] hr = c;
			int[] hr = c;

			for (int i = 0; i < 17; ++i)
			{
				int u = 0;
				/* Basic multiply to compute term i */
				for (int j = 0; j <= i; ++j)
				{
					u += h[j] * r[i - j];
				}

				/*
				 * Modular reduction
				 *
				 * Shift overflow >> 130 bits == (>> 17 bytes = 136 bits) + (<< 6 bits = * 64)
				 *
				 * Reduction mod 2^130-5 leaves 5x remainder, so 64 * 5 = 320.
				 */
				for (int j = i + 1; j < 17; ++j)
				{
					u += 320 * h[j] * r[i + 17 - j];
				}
				hr[i] = u;
			}
			JavaSystem.arraycopy(hr, 0, h, 0, h.Length);
			squeeze(h);
		}

		/// <summary>
		/// Propagate carries following a modular multiplication.
		/// </summary>
		private static void squeeze(int[] h)
		{
			int u = 0;
			for (int j = 0; j < 16; ++j)
			{
				u += h[j];
				h[j] = u & 255;
				u >>= 8;
			}
			u += h[16];
			h[16] = u & 3;
			u = 5 * (u >> 2);
			for (int j = 0; j < 16; ++j)
			{
				u += h[j];
				h[j] = u & 255;
				u >>= 8;
			}
			u += h[16];
			h[16] = u;
		}

		/// <summary>
		/// Constant time correction of h to be &lt; p (2^130 - 5).
		/// </summary>
		private void freeze(int[] h)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int[] horig = c;
			int[] horig = c;
			JavaSystem.arraycopy(h, 0, horig, 0, h.Length);

			add(h, minusp);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int negative = -(h[16] >> 7);
			int negative = -(h[16] >> 7);
			for (int j = 0; j < 17; ++j)
			{
				h[j] ^= negative & (horig[j] ^ h[j]);
			}
		}

	}

}