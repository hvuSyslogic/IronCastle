using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using RC5Parameters = org.bouncycastle.crypto.@params.RC5Parameters;

	/// <summary>
	/// The specification for RC5 came from the <code>RC5 Encryption Algorithm</code>
	/// publication in RSA CryptoBytes, Spring of 1995. 
	/// <em>http://www.rsasecurity.com/rsalabs/cryptobytes</em>.
	/// <para>
	/// This implementation is set to work with a 64 bit word size.
	/// </para>
	/// <para>
	/// Implementation courtesy of Tito Pena.
	/// </para>
	/// </summary>
	public class RC564Engine : BlockCipher
	{
		private const int wordSize = 64;
		private static readonly int bytesPerWord = wordSize / 8;

		/*
		 * the number of rounds to perform
		 */
		private int _noRounds;

		/*
		 * the expanded key array of size 2*(rounds + 1)
		 */
		private long[] _S;

		/*
		 * our "magic constants" for wordSize 62
		 *
		 * Pw = Odd((e-2) * 2^wordsize)
		 * Qw = Odd((o-2) * 2^wordsize)
		 *
		 * where e is the base of natural logarithms (2.718281828...)
		 * and o is the golden ratio (1.61803398...)
		 */
		private const long P64 = unchecked((long)0xb7e151628aed2a6bL);
		private const long Q64 = unchecked((long)0x9e3779b97f4a7c15L);

		private bool forEncryption;

		/// <summary>
		/// Create an instance of the RC5 encryption algorithm
		/// and set some defaults
		/// </summary>
		public RC564Engine()
		{
			_noRounds = 12;
			_S = null;
		}

		public virtual string getAlgorithmName()
		{
			return "RC5-64";
		}

		public virtual int getBlockSize()
		{
			return 2 * bytesPerWord;
		}

		/// <summary>
		/// initialise a RC5-64 cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is RC5Parameters))
			{
				throw new IllegalArgumentException("invalid parameter passed to RC564 init - " + @params.GetType().getName());
			}

			RC5Parameters p = (RC5Parameters)@params;

			this.forEncryption = forEncryption;

			_noRounds = p.getRounds();

			setKey(p.getKey());
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			return (forEncryption) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
		}

		public virtual void reset()
		{
		}

		/// <summary>
		/// Re-key the cipher.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="key">  the key to be used </param>
		private void setKey(byte[] key)
		{
			//
			// KEY EXPANSION:
			//
			// There are 3 phases to the key expansion.
			//
			// Phase 1:
			//   Copy the secret key K[0...b-1] into an array L[0..c-1] of
			//   c = ceil(b/u), where u = wordSize/8 in little-endian order.
			//   In other words, we fill up L using u consecutive key bytes
			//   of K. Any unfilled byte positions in L are zeroed. In the
			//   case that b = c = 0, set c = 1 and L[0] = 0.
			//
			long[] L = new long[(key.Length + (bytesPerWord - 1)) / bytesPerWord];

		    {for (int i = 0; i != key.Length; i++)
			{
				L[i / bytesPerWord] += (long)(key[i] & 0xff) << (8 * (i % bytesPerWord));
			}}

			//
			// Phase 2:
			//   Initialize S to a particular fixed pseudo-random bit pattern
			//   using an arithmetic progression modulo 2^wordsize determined
			//   by the magic numbers, Pw & Qw.
			//
			_S = new long[2 * (_noRounds + 1)];

			_S[0] = P64;
		    {for (int i = 1; i < _S.Length; i++)
			{
				_S[i] = (_S[i - 1] + Q64);
			}}

			//
			// Phase 3:
			//   Mix in the user's secret key in 3 passes over the arrays S & L.
			//   The max of the arrays sizes is used as the loop control
			//
			int iter;

			if (L.Length > _S.Length)
			{
				iter = 3 * L.Length;
			}
			else
			{
				iter = 3 * _S.Length;
			}

			long A = 0, B = 0;
		    {int i = 0, j = 0;

			for (int k = 0; k < iter; k++)
			{
				A = _S[i] = rotateLeft(_S[i] + A + B, 3);
				B = L[j] = rotateLeft(L[j] + A + B, A + B);
				i = (i + 1) % _S.Length;
				j = (j + 1) % L.Length;
			}
		    }
        }

		/// <summary>
		/// Encrypt the given block starting at the given offset and place
		/// the result in the provided buffer starting at the given offset.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="in">      in byte buffer containing data to encrypt </param>
		/// <param name="inOff">   offset into src buffer </param>
		/// <param name="out">     out buffer where encrypted data is written </param>
		/// <param name="outOff">  offset into out buffer </param>
		private int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			long A = bytesToWord(@in, inOff) + _S[0];
			long B = bytesToWord(@in, inOff + bytesPerWord) + _S[1];

			for (int i = 1; i <= _noRounds; i++)
			{
				A = rotateLeft(A ^ B, B) + _S[2 * i];
				B = rotateLeft(B ^ A, A) + _S[2 * i + 1];
			}

			wordToBytes(A, @out, outOff);
			wordToBytes(B, @out, outOff + bytesPerWord);

			return 2 * bytesPerWord;
		}

		private int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			long A = bytesToWord(@in, inOff);
			long B = bytesToWord(@in, inOff + bytesPerWord);

			for (int i = _noRounds; i >= 1; i--)
			{
				B = rotateRight(B - _S[2 * i + 1], A) ^ A;
				A = rotateRight(A - _S[2 * i], B) ^ B;
			}

			wordToBytes(A - _S[0], @out, outOff);
			wordToBytes(B - _S[1], @out, outOff + bytesPerWord);

			return 2 * bytesPerWord;
		}


        //////////////////////////////////////////////////////////////
        //
        // PRIVATE Helper Methods
        //
        //////////////////////////////////////////////////////////////

        /// <summary>
        /// Perform a left "spin" of the word. The rotation of the given
        /// word <em>x</em> is rotated left by <em>y</em> bits.
        /// Only the <em>lg(wordSize)</em> low-order bits of <em>y</em>
        /// are used to determine the rotation amount. Here it is 
        /// assumed that the wordsize used is a power of 2.
        /// <para>
        /// </para>
        /// </summary>
        /// <param name="x">  word to rotate </param>
        /// <param name="y">    number of bits to rotate % wordSize </param>
        private long rotateLeft(long x, long y)
        {
            return ((long)((ulong)(x << (int)(y & (wordSize - 1))) | ((ulong)x >> (int)(wordSize - (y & (wordSize - 1))))));
        }

        /// <summary>
        /// Perform a right "spin" of the word. The rotation of the given
        /// word <em>x</em> is rotated left by <em>y</em> bits.
        /// Only the <em>lg(wordSize)</em> low-order bits of <em>y</em>
        /// are used to determine the rotation amount. Here it is 
        /// assumed that the wordsize used is a power of 2.
        /// <para>
        /// </para>
        /// </summary>
        /// <param name="x">  word to rotate </param>
        /// <param name="y">    number of bits to rotate % wordSize </param>
        private long rotateRight(long x, long y)
		{
		    return ((long)(((ulong)x >> (int)(y & (wordSize - 1))) |(ulong)(x << (int)(wordSize - (y & (wordSize - 1))))));
		}

		private long bytesToWord(byte[] src, int srcOff)
		{
			long word = 0;

			for (int i = bytesPerWord - 1; i >= 0; i--)
			{
				word = (word << 8) + (src[i + srcOff] & 0xff);
			}

			return word;
		}

		private void wordToBytes(long word, byte[] dst, int dstOff)
		{
			for (int i = 0; i < bytesPerWord; i++)
			{
				dst[i + dstOff] = (byte)word;
				word = (long)((ulong)word >> 8);
			}
		}
	}

}