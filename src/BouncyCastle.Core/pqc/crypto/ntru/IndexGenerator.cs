using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.ntru
{
	using Digest = org.bouncycastle.crypto.Digest;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// An implementation of the Index Generation Function in IEEE P1363.1.
	/// </summary>
	public class IndexGenerator
	{
		private byte[] seed;
		private int N;
		private int c;
		private int minCallsR;
		private int totLen;
		private int remLen;
		private BitString buf;
		private int counter;
		private bool initialized;
		private Digest hashAlg;
		private int hLen;

		/// <summary>
		/// Constructs a new index generator.
		/// </summary>
		/// <param name="seed">   a seed of arbitrary length to initialize the index generator with </param>
		/// <param name="params"> NtruEncrypt parameters </param>
		public IndexGenerator(byte[] seed, NTRUEncryptionParameters @params)
		{
			this.seed = seed;
			N = @params.N;
			c = @params.c;
			minCallsR = @params.minCallsR;

			totLen = 0;
			remLen = 0;
			counter = 0;
			hashAlg = @params.hashAlg;

			hLen = hashAlg.getDigestSize(); // hash length
			initialized = false;
		}

		/*
		 * Returns a number <code>i</code> such that <code>0 &lt;= i &lt; N</code>.
		 */
		public virtual int nextIndex()
		{
			if (!initialized)
			{
				buf = new BitString();
				byte[] hash = new byte[hashAlg.getDigestSize()];
				while (counter < minCallsR)
				{
					appendHash(buf, hash);
					counter++;
				}
				totLen = minCallsR * 8 * hLen;
				remLen = totLen;
				initialized = true;
			}

			while (true)
			{
				totLen += c;
				BitString M = buf.getTrailing(remLen);
				if (remLen < c)
				{
					int tmpLen = c - remLen;
					int cThreshold = counter + (tmpLen + hLen - 1) / hLen;
					byte[] hash = new byte[hashAlg.getDigestSize()];
					while (counter < cThreshold)
					{
						appendHash(M, hash);
						counter++;
						if (tmpLen > 8 * hLen)
						{
							tmpLen -= 8 * hLen;
						}
					}
					remLen = 8 * hLen - tmpLen;
					buf = new BitString();
					buf.appendBits(hash);
				}
				else
				{
					remLen -= c;
				}

				int i = M.getLeadingAsInt(c); // assume c<32
				if (i < (1 << c) - ((1 << c) % N))
				{
					return i % N;
				}
			}
		}

		private void appendHash(BitString m, byte[] hash)
		{
			hashAlg.update(seed, 0, seed.Length);

			putInt(hashAlg, counter);

			hashAlg.doFinal(hash, 0);

			m.appendBits(hash);
		}

		private void putInt(Digest hashAlg, int counter)
		{
			hashAlg.update((byte)(counter >> 24));
			hashAlg.update((byte)(counter >> 16));
			hashAlg.update((byte)(counter >> 8));
			hashAlg.update((byte)counter);
		}

		/// <summary>
		/// Represents a string of bits and supports appending, reading the head, and reading the tail.
		/// </summary>
		public class BitString
		{
			internal byte[] bytes = new byte[4];
			internal int numBytes; // includes the last byte even if only some of its bits are used
			internal int lastByteBits; // lastByteBits <= 8

			/// <summary>
			/// Appends all bits in a byte array to the end of the bit string.
			/// </summary>
			/// <param name="bytes"> a byte array </param>
			public virtual void appendBits(byte[] bytes)
			{
				for (int i = 0; i != bytes.Length; i++)
				{
					appendBits(bytes[i]);
				}
			}

			/// <summary>
			/// Appends all bits in a byte to the end of the bit string.
			/// </summary>
			/// <param name="b"> a byte </param>
			public virtual void appendBits(byte b)
			{
				if (numBytes == bytes.Length)
				{
					bytes = copyOf(bytes, 2 * bytes.Length);
				}

				if (numBytes == 0)
				{
					numBytes = 1;
					bytes[0] = b;
					lastByteBits = 8;
				}
				else if (lastByteBits == 8)
				{
					bytes[numBytes++] = b;
				}
				else
				{
					int s = 8 - lastByteBits;
					bytes[numBytes - 1] |= (byte)((b & 0xFF) << lastByteBits);
					bytes[numBytes++] = (byte)((b & 0xFF) >> s);
				}
			}

			/// <summary>
			/// Returns the last <code>numBits</code> bits from the end of the bit string.
			/// </summary>
			/// <param name="numBits"> number of bits </param>
			/// <returns> a new <code>BitString</code> of length <code>numBits</code> </returns>
			public virtual BitString getTrailing(int numBits)
			{
				BitString newStr = new BitString();
				newStr.numBytes = (numBits + 7) / 8;
				newStr.bytes = new byte[newStr.numBytes];
				for (int i = 0; i < newStr.numBytes; i++)
				{
					newStr.bytes[i] = bytes[i];
				}

				newStr.lastByteBits = numBits % 8;
				if (newStr.lastByteBits == 0)
				{
					newStr.lastByteBits = 8;
				}
				else
				{
					int s = 32 - newStr.lastByteBits;
					newStr.bytes[newStr.numBytes - 1] = (byte)((int)((uint)newStr.bytes[newStr.numBytes - 1] << s >> s));
				}

				return newStr;
			}

			/// <summary>
			/// Returns up to 32 bits from the beginning of the bit string.
			/// </summary>
			/// <param name="numBits"> number of bits </param>
			/// <returns> an <code>int</code> whose lower <code>numBits</code> bits are the beginning of the bit string </returns>
			public virtual int getLeadingAsInt(int numBits)
			{
				int startBit = (numBytes - 1) * 8 + lastByteBits - numBits;
				int startByte = startBit / 8;

				int startBitInStartByte = startBit % 8;
				int sum = (int)((uint)(bytes[startByte] & 0xFF) >> startBitInStartByte);
				int shift = 8 - startBitInStartByte;
				for (int i = startByte + 1; i < numBytes; i++)
				{
					sum |= (bytes[i] & 0xFF) << shift;
					shift += 8;
				}

				return sum;
			}

			public virtual byte[] getBytes()
			{
				return Arrays.clone(bytes);
			}
		}

		private static byte[] copyOf(byte[] src, int len)
		{
			byte[] tmp = new byte[len];

			JavaSystem.arraycopy(src, 0, tmp, 0, len < src.Length ? len : src.Length);

			return tmp;
		}
	}
}