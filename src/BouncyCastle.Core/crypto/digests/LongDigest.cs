using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{
		
	/// <summary>
	/// Base class for SHA-384 and SHA-512.
	/// </summary>
	public abstract class LongDigest : ExtendedDigest, Memoable, EncodableDigest
	{
		public abstract byte[] getEncodedState();
		public abstract void reset(Memoable other);
		public abstract Memoable copy();
		public abstract int doFinal(byte[] @out, int outOff);
		public abstract int getDigestSize();
		public abstract string getAlgorithmName();
		private const int BYTE_LENGTH = 128;

		private byte[] xBuf = new byte[8];
		private int xBufOff;

		private long byteCount1;
		private long byteCount2;

		protected internal ulong H1, H2, H3, H4, H5, H6, H7, H8;

		private ulong[] W = new ulong[80];
		private int wOff;

		/// <summary>
		/// Constructor for variable length word
		/// </summary>
		public LongDigest()
		{
			xBufOff = 0;

			reset();
		}

		/// <summary>
		/// Copy constructor.  We are using copy constructors in place
		/// of the Object.clone() interface as this interface is not
		/// supported by J2ME.
		/// </summary>
		public LongDigest(LongDigest t)
		{
			copyIn(t);
		}

		public virtual void copyIn(LongDigest t)
		{
			JavaSystem.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

			xBufOff = t.xBufOff;
			byteCount1 = t.byteCount1;
			byteCount2 = t.byteCount2;

			H1 = t.H1;
			H2 = t.H2;
			H3 = t.H3;
			H4 = t.H4;
			H5 = t.H5;
			H6 = t.H6;
			H7 = t.H7;
			H8 = t.H8;

			JavaSystem.arraycopy(t.W, 0, W, 0, t.W.Length);
			wOff = t.wOff;
		}

		public virtual void populateState(byte[] state)
		{
			JavaSystem.arraycopy(xBuf, 0, state, 0, xBufOff);
			Pack.intToBigEndian(xBufOff, state, 8);
			Pack.longToBigEndian(byteCount1, state, 12);
			Pack.longToBigEndian(byteCount2, state, 20);
			Pack.ulongToBigEndian(H1, state, 28);
			Pack.ulongToBigEndian(H2, state, 36);
			Pack.ulongToBigEndian(H3, state, 44);
			Pack.ulongToBigEndian(H4, state, 52);
			Pack.ulongToBigEndian(H5, state, 60);
			Pack.ulongToBigEndian(H6, state, 68);
			Pack.ulongToBigEndian(H7, state, 76);
			Pack.ulongToBigEndian(H8, state, 84);

			Pack.intToBigEndian(wOff, state, 92);
			for (int i = 0; i < wOff; i++)
			{
				Pack.ulongToBigEndian(W[i], state, 96 + (i * 8));
			}
		}

		public virtual void restoreState(byte[] encodedState)
		{
			xBufOff = Pack.bigEndianToInt(encodedState, 8);
			JavaSystem.arraycopy(encodedState, 0, xBuf, 0, xBufOff);
			byteCount1 = Pack.bigEndianToLong(encodedState, 12);
			byteCount2 = Pack.bigEndianToLong(encodedState, 20);

			H1 = Pack.bigEndianToULong(encodedState, 28);
			H2 = Pack.bigEndianToULong(encodedState, 36);
			H3 = Pack.bigEndianToULong(encodedState, 44);
			H4 = Pack.bigEndianToULong(encodedState, 52);
			H5 = Pack.bigEndianToULong(encodedState, 60);
			H6 = Pack.bigEndianToULong(encodedState, 68);
			H7 = Pack.bigEndianToULong(encodedState, 76);
			H8 = Pack.bigEndianToULong(encodedState, 84);

			wOff = Pack.bigEndianToInt(encodedState, 92);
			for (int i = 0; i < wOff; i++)
			{
				W[i] = Pack.bigEndianToULong(encodedState, 96 + (i * 8));
			}
		}

		public virtual int getEncodedStateSize()
		{
			return 96 + (wOff * 8);
		}

		public virtual void update(byte @in)
		{
			xBuf[xBufOff++] = @in;

			if (xBufOff == xBuf.Length)
			{
				processWord(xBuf, 0);
				xBufOff = 0;
			}

			byteCount1++;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			//
			// fill the current word
			//
			while ((xBufOff != 0) && (len > 0))
			{
				update(@in[inOff]);

				inOff++;
				len--;
			}

			//
			// process whole words.
			//
			while (len > xBuf.Length)
			{
				processWord(@in, inOff);

				inOff += xBuf.Length;
				len -= xBuf.Length;
				byteCount1 += xBuf.Length;
			}

			//
			// load in the remainder.
			//
			while (len > 0)
			{
				update(@in[inOff]);

				inOff++;
				len--;
			}
		}

		public virtual void finish()
		{
			adjustByteCounts();

			ulong lowBitLength = (ulong) (byteCount1 << 3);
			ulong hiBitLength = (ulong) byteCount2;

			//
			// add the pad bytes.
			//
			update(unchecked(128));

			while (xBufOff != 0)
			{
				update(0);
			}

			processLength(lowBitLength, hiBitLength);

			processBlock();
		}

		public virtual void reset()
		{
			byteCount1 = 0;
			byteCount2 = 0;

			xBufOff = 0;
			for (int i = 0; i < xBuf.Length; i++)
			{
				xBuf[i] = 0;
			}

			wOff = 0;
			for (int i = 0; i != W.Length; i++)
			{
				W[i] = 0;
			}
		}

		public virtual int getByteLength()
		{
			return BYTE_LENGTH;
		}

		public virtual void processWord(byte[] @in, int inOff)
		{
			W[wOff] = Pack.bigEndianToULong(@in, inOff);

			if (++wOff == 16)
			{
				processBlock();
			}
		}

		/// <summary>
		/// adjust the byte counts so that byteCount2 represents the
		/// upper long (less 3 bits) word of the byte count.
		/// </summary>
		private void adjustByteCounts()
		{
			if (byteCount1 > 0x1fffffffffffffffL)
			{
				byteCount2 += ((long)((ulong)byteCount1 >> 61));
				byteCount1 &= 0x1fffffffffffffffL;
			}
		}

		public virtual void processLength(ulong lowW, ulong hiW)
		{
			if (wOff > 14)
			{
				processBlock();
			}

			W[14] = hiW;
			W[15] = lowW;
		}

		public virtual void processBlock()
		{
			adjustByteCounts();

			//
			// expand 16 word block into 80 word blocks.
			//
		    {for (int t = 16; t <= 79; t++)
			{
				W[t] = Sigma1(W[t - 2]) + W[t - 7] + Sigma0(W[t - 15]) + W[t - 16];
			}}

			//
			// set up working variables.
			//
			ulong a = H1;
			ulong b = H2;
			ulong c = H3;
			ulong d = H4;
			ulong e = H5;
			ulong f = H6;
			ulong g = H7;
			ulong h = H8;

		    {int t = 0;
			for (int i = 0; i < 10; i++)
			{
			  // t = 8 * i
			  h += Sum1(e) + Ch(e, f, g) + K[t] + W[t++];
			  d += h;
			  h += Sum0(a) + Maj(a, b, c);

			  // t = 8 * i + 1
			  g += Sum1(d) + Ch(d, e, f) + K[t] + W[t++];
			  c += g;
			  g += Sum0(h) + Maj(h, a, b);

			  // t = 8 * i + 2
			  f += Sum1(c) + Ch(c, d, e) + K[t] + W[t++];
			  b += f;
			  f += Sum0(g) + Maj(g, h, a);

			  // t = 8 * i + 3
			  e += Sum1(b) + Ch(b, c, d) + K[t] + W[t++];
			  a += e;
			  e += Sum0(f) + Maj(f, g, h);

			  // t = 8 * i + 4
			  d += Sum1(a) + Ch(a, b, c) + K[t] + W[t++];
			  h += d;
			  d += Sum0(e) + Maj(e, f, g);

			  // t = 8 * i + 5
			  c += Sum1(h) + Ch(h, a, b) + K[t] + W[t++];
			  g += c;
			  c += Sum0(d) + Maj(d, e, f);

			  // t = 8 * i + 6
			  b += Sum1(g) + Ch(g, h, a) + K[t] + W[t++];
			  f += b;
			  b += Sum0(c) + Maj(c, d, e);

			  // t = 8 * i + 7
			  a += Sum1(f) + Ch(f, g, h) + K[t] + W[t++];
			  e += a;
			  a += Sum0(b) + Maj(b, c, d);
			}

			H1 += a;
			H2 += b;
			H3 += c;
			H4 += d;
			H5 += e;
			H6 += f;
			H7 += g;
			H8 += h;
		    }
            //
            // reset the offset and clean out the word buffer.
            //
            wOff = 0;
			for (int i = 0; i < 16; i++)
			{
				W[i] = 0;
			}
		}

		/* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
		private ulong Ch(ulong x, ulong y, ulong z)
		{
			return ((x & y) ^ ((~x) & z));
		}

		private ulong Maj(ulong x, ulong y, ulong z)
		{
			return ((x & y) ^ (x & z) ^ (y & z));
		}

		private ulong Sum0(ulong x)
		{
			return ((x << 36) | x >> 28) ^ ((x << 30) | x >> 34) ^ ((x << 25) | x >> 39);
		}

		private ulong Sum1(ulong x)
		{
			return ((x << 50) | x >> 14) ^ ((x << 46) | x >> 18) ^ ((x << 23) | x >> 41);
		}

		private ulong Sigma0(ulong x)
		{
			return ((x << 63) | x >> 1) ^ ((x << 56) | x >> 8) ^ x >> 7;
		}

		private ulong Sigma1(ulong x)
		{
			return ((x << 45) | x >> 19) ^ ((x << 3) | x >> 61) ^ x >> 6;
		}

		/* SHA-384 and SHA-512 Constants
		 * (represent the first 64 bits of the fractional parts of the
		 * cube roots of the first sixty-four prime numbers)
		 */
		internal static readonly ulong[] K = new ulong[] {0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, unchecked(0xb5c0fbcfec4d3b2fUL), unchecked(0xe9b5dba58189dbbcUL), 0x3956c25bf348b538UL, 0x59f111f1b605d019UL, unchecked(0x923f82a4af194f9bUL), unchecked(0xab1c5ed5da6d8118UL), unchecked(0xd807aa98a3030242UL), 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL, 0x72be5d74f27b896fUL, unchecked(0x80deb1fe3b1696b1UL), unchecked(0x9bdc06a725c71235UL), unchecked(0xc19bf174cf692694UL), unchecked(0xe49b69c19ef14ad2UL), unchecked(0xefbe4786384f25e3UL), 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL, unchecked(0x983e5152ee66dfabUL), unchecked(0xa831c66d2db43210UL), unchecked(0xb00327c898fb213fUL), unchecked(0xbf597fc7beef0ee4UL), unchecked(0xc6e00bf33da88fc2UL), unchecked(0xd5a79147930aa725UL), 0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL, 0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, unchecked(0x81c2c92e47edaee6UL), unchecked(0x92722c851482353bUL), unchecked(0xa2bfe8a14cf10364UL), unchecked(0xa81a664bbc423001UL), unchecked(0xc24b8b70d0f89791UL), unchecked(0xc76c51a30654be30UL), unchecked(0xd192e819d6ef5218UL), unchecked(0xd69906245565a910UL), unchecked(0xf40e35855771202aUL), 0x106aa07032bbd1b8UL, 0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, unchecked(0x84c87814a1f0ab72UL), unchecked(0x8cc702081a6439ecUL), unchecked(0x90befffa23631e28UL), unchecked(0xa4506cebde82bde9UL), unchecked(0xbef9a3f7b2c67915UL), unchecked(0xc67178f2e372532bUL), unchecked(0xca273eceea26619cUL), unchecked(0xd186b8c721c0c207UL), unchecked(0xeada7dd6cde0eb1eUL), unchecked(0xf57d4f7fee6ed178UL), 0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL, 0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL};

	}

}