using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.macs
{
		
	/// <summary>
	/// Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
	/// Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
	/// <para>
	/// "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
	/// compression rounds and the number of finalization rounds. A compression round is identical to a
	/// finalization round and this round function is called SipRound. Given a 128-bit key k and a
	/// (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
	/// </para>
	/// </summary>
	public class SipHash : Mac
	{
		protected internal readonly int c, d;

		protected internal long k0, k1;
		protected internal long v0, v1, v2, v3;

		protected internal long m = 0;
		protected internal int wordPos = 0;
		protected internal int wordCount = 0;

		/// <summary>
		/// SipHash-2-4
		/// </summary>
		public SipHash()
		{
			// use of 'this' confuses the flow analyser on earlier JDKs.
			this.c = 2;
			this.d = 4;
		}

		/// <summary>
		/// SipHash-c-d
		/// </summary>
		/// <param name="c"> the number of compression rounds </param>
		/// <param name="d"> the number of finalization rounds </param>
		public SipHash(int c, int d)
		{
			this.c = c;
			this.d = d;
		}

		public virtual string getAlgorithmName()
		{
			return "SipHash-" + c + "-" + d;
		}

		public virtual int getMacSize()
		{
			return 8;
		}

		public virtual void init(CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("'params' must be an instance of KeyParameter");
			}
			KeyParameter keyParameter = (KeyParameter)@params;
			byte[] key = keyParameter.getKey();
			if (key.Length != 16)
			{
				throw new IllegalArgumentException("'params' must be a 128-bit key");
			}

			this.k0 = Pack.littleEndianToLong(key, 0);
			this.k1 = Pack.littleEndianToLong(key, 8);

			reset();
		}

		public virtual void update(byte input)
		{
			m = (long)((ulong)m >> 8);
			m |= (input & 0xffL) << 56;

			if (++wordPos == 8)
			{
				processMessageWord();
				wordPos = 0;
			}
		}

		public virtual void update(byte[] input, int offset, int length)
		{
			int i = 0, fullWords = length & ~7;
			if (wordPos == 0)
			{
				for (; i < fullWords; i += 8)
				{
					m = Pack.littleEndianToLong(input, offset + i);
					processMessageWord();
				}
				for (; i < length; ++i)
				{
					m = (long)((ulong)m >> 8);
					m |= (input[offset + i] & 0xffL) << 56;
				}
				wordPos = length - fullWords;
			}
			else
			{
				int bits = wordPos << 3;
				for (; i < fullWords; i += 8)
				{
					long n = Pack.littleEndianToLong(input, offset + i);
					m = (n << bits) | ((long)((ulong)m >> -bits));
					processMessageWord();
					m = n;
				}
				for (; i < length; ++i)
				{
					m = (long)((ulong)m >> 8);
					m |= (input[offset + i] & 0xffL) << 56;

					if (++wordPos == 8)
					{
						processMessageWord();
						wordPos = 0;
					}
				}
			}
		}

		public virtual long doFinal()
		{
			// NOTE: 2 distinct shifts to avoid "64-bit shift" when wordPos == 0
			m = (long)((ulong)m >> ((7 - wordPos) << 3));
			m = (long)((ulong)m >> 8);
			m |= (((wordCount << 3) + wordPos) & 0xffL) << 56;

			processMessageWord();

			v2 ^= 0xffL;

			applySipRounds(d);

			long result = v0 ^ v1 ^ v2 ^ v3;

			reset();

			return result;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			long result = doFinal();
			Pack.longToLittleEndian(result, @out, outOff);
			return 8;
		}

		public virtual void reset()
		{
			v0 = k0 ^ 0x736f6d6570736575L;
			v1 = k1 ^ 0x646f72616e646f6dL;
			v2 = k0 ^ 0x6c7967656e657261L;
			v3 = k1 ^ 0x7465646279746573L;

			m = 0;
			wordPos = 0;
			wordCount = 0;
		}

		public virtual void processMessageWord()
		{
			++wordCount;
			v3 ^= m;
			applySipRounds(c);
			v0 ^= m;
		}

		public virtual void applySipRounds(int n)
		{
			long r0 = v0, r1 = v1, r2 = v2, r3 = v3;

			for (int r = 0; r < n; ++r)
			{
				r0 += r1;
				r2 += r3;
				r1 = rotateLeft(r1, 13);
				r3 = rotateLeft(r3, 16);
				r1 ^= r0;
				r3 ^= r2;
				r0 = rotateLeft(r0, 32);
				r2 += r1;
				r0 += r3;
				r1 = rotateLeft(r1, 17);
				r3 = rotateLeft(r3, 21);
				r1 ^= r2;
				r3 ^= r0;
				r2 = rotateLeft(r2, 32);
			}

			v0 = r0;
			v1 = r1;
			v2 = r2;
			v3 = r3;
		}

		protected internal static long rotateLeft(long x, int n)
		{
			return (x << n) | ((long)((ulong)x >> -n));
		}
	}

}