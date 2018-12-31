﻿using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{

		

	/// <summary>
	/// FIPS 180-2 implementation of SHA-256.
	/// 
	/// <pre>
	///         block  word  digest
	/// SHA-1   512    32    160
	/// SHA-256 512    32    256
	/// SHA-384 1024   64    384
	/// SHA-512 1024   64    512
	/// </pre>
	/// </summary>
	public class SHA256Digest : GeneralDigest, EncodableDigest
	{
		private const int DIGEST_LENGTH = 32;

		private int H1, H2, H3, H4, H5, H6, H7, H8;

		private int[] X = new int[64];
		private int xOff;

		/// <summary>
		/// Standard constructor
		/// </summary>
		public SHA256Digest()
		{
			reset();
		}

		/// <summary>
		/// Copy constructor.  This will copy the state of the provided
		/// message digest.
		/// </summary>
		public SHA256Digest(SHA256Digest t) : base(t)
		{

			copyIn(t);
		}

		private void copyIn(SHA256Digest t)
		{
			base.copyIn(t);

			H1 = t.H1;
			H2 = t.H2;
			H3 = t.H3;
			H4 = t.H4;
			H5 = t.H5;
			H6 = t.H6;
			H7 = t.H7;
			H8 = t.H8;

			JavaSystem.arraycopy(t.X, 0, X, 0, t.X.Length);
			xOff = t.xOff;
		}

		/// <summary>
		/// State constructor - create a digest initialised with the state of a previous one.
		/// </summary>
		/// <param name="encodedState"> the encoded state from the originating digest. </param>
		public SHA256Digest(byte[] encodedState) : base(encodedState)
		{

			H1 = Pack.bigEndianToInt(encodedState, 16);
			H2 = Pack.bigEndianToInt(encodedState, 20);
			H3 = Pack.bigEndianToInt(encodedState, 24);
			H4 = Pack.bigEndianToInt(encodedState, 28);
			H5 = Pack.bigEndianToInt(encodedState, 32);
			H6 = Pack.bigEndianToInt(encodedState, 36);
			H7 = Pack.bigEndianToInt(encodedState, 40);
			H8 = Pack.bigEndianToInt(encodedState, 44);

			xOff = Pack.bigEndianToInt(encodedState, 48);
			for (int i = 0; i != xOff; i++)
			{
				X[i] = Pack.bigEndianToInt(encodedState, 52 + (i * 4));
			}
		}


		public override string getAlgorithmName()
		{
			return "SHA-256";
		}

		public override int getDigestSize()
		{
			return DIGEST_LENGTH;
		}

		public override void processWord(byte[] @in, int inOff)
		{
			// Note: Inlined for performance
	//        X[xOff] = Pack.bigEndianToInt(in, inOff);
			int n = @in[inOff] << 24;
			n |= (@in[++inOff] & 0xff) << 16;
			n |= (@in[++inOff] & 0xff) << 8;
			n |= (@in[++inOff] & 0xff);
			X[xOff] = n;

			if (++xOff == 16)
			{
				processBlock();
			}
		}

		public override void processLength(long bitLength)
		{
			if (xOff > 14)
			{
				processBlock();
			}

			X[14] = (int)((long)((ulong)bitLength >> 32));
			X[15] = unchecked((int)(bitLength & 0xffffffff));
		}

		public override int doFinal(byte[] @out, int outOff)
		{
			finish();

			Pack.intToBigEndian(H1, @out, outOff);
			Pack.intToBigEndian(H2, @out, outOff + 4);
			Pack.intToBigEndian(H3, @out, outOff + 8);
			Pack.intToBigEndian(H4, @out, outOff + 12);
			Pack.intToBigEndian(H5, @out, outOff + 16);
			Pack.intToBigEndian(H6, @out, outOff + 20);
			Pack.intToBigEndian(H7, @out, outOff + 24);
			Pack.intToBigEndian(H8, @out, outOff + 28);

			reset();

			return DIGEST_LENGTH;
		}

		/// <summary>
		/// reset the chaining variables
		/// </summary>
		public override void reset()
		{
			base.reset();

			/* SHA-256 initial hash value
			 * The first 32 bits of the fractional parts of the square roots
			 * of the first eight prime numbers
			 */

			H1 = 0x6a09e667;
			H2 = unchecked((int)0xbb67ae85);
			H3 = 0x3c6ef372;
			H4 = unchecked((int)0xa54ff53a);
			H5 = 0x510e527f;
			H6 = unchecked((int)0x9b05688c);
			H7 = 0x1f83d9ab;
			H8 = 0x5be0cd19;

			xOff = 0;
			for (int i = 0; i != X.Length; i++)
			{
				X[i] = 0;
			}
		}

		public override void processBlock()
		{
			//
			// expand 16 word block into 64 word blocks.
			//
			{
			for (int t = 16; t <= 63; t++)
			{
				X[t] = Theta1(X[t - 2]) + X[t - 7] + Theta0(X[t - 15]) + X[t - 16];
			}
			}

            //
            // set up working variables.
            //
            int a = H1;
			int b = H2;
			int c = H3;
			int d = H4;
			int e = H5;
			int f = H6;
			int g = H7;
			int h = H8;

		    {
			int t = 0;
			for (int i = 0; i < 8; i++)
			{
				// t = 8 * i
				h += Sum1(e) + Ch(e, f, g) + K[t] + X[t];
				d += h;
				h += Sum0(a) + Maj(a, b, c);
				++t;

				// t = 8 * i + 1
				g += Sum1(d) + Ch(d, e, f) + K[t] + X[t];
				c += g;
				g += Sum0(h) + Maj(h, a, b);
				++t;

				// t = 8 * i + 2
				f += Sum1(c) + Ch(c, d, e) + K[t] + X[t];
				b += f;
				f += Sum0(g) + Maj(g, h, a);
				++t;

				// t = 8 * i + 3
				e += Sum1(b) + Ch(b, c, d) + K[t] + X[t];
				a += e;
				e += Sum0(f) + Maj(f, g, h);
				++t;

				// t = 8 * i + 4
				d += Sum1(a) + Ch(a, b, c) + K[t] + X[t];
				h += d;
				d += Sum0(e) + Maj(e, f, g);
				++t;

				// t = 8 * i + 5
				c += Sum1(h) + Ch(h, a, b) + K[t] + X[t];
				g += c;
				c += Sum0(d) + Maj(d, e, f);
				++t;

				// t = 8 * i + 6
				b += Sum1(g) + Ch(g, h, a) + K[t] + X[t];
				f += b;
				b += Sum0(c) + Maj(c, d, e);
				++t;

				// t = 8 * i + 7
				a += Sum1(f) + Ch(f, g, h) + K[t] + X[t];
				e += a;
				a += Sum0(b) + Maj(b, c, d);
				++t;
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
            xOff = 0;
			for (int i = 0; i < 16; i++)
			{
				X[i] = 0;
			}
		}

		/* SHA-256 functions */
		private int Ch(int x, int y, int z)
		{
			return (x & y) ^ ((~x) & z);
		}

		private int Maj(int x, int y, int z)
		{
			return (x & y) ^ (x & z) ^ (y & z);
		}

		private int Sum0(int x)
		{
			return (((int)((uint)x >> 2)) | (x << 30)) ^ (((int)((uint)x >> 13)) | (x << 19)) ^ (((int)((uint)x >> 22)) | (x << 10));
		}

		private int Sum1(int x)
		{
			return (((int)((uint)x >> 6)) | (x << 26)) ^ (((int)((uint)x >> 11)) | (x << 21)) ^ (((int)((uint)x >> 25)) | (x << 7));
		}

		private int Theta0(int x)
		{
			return (((int)((uint)x >> 7)) | (x << 25)) ^ (((int)((uint)x >> 18)) | (x << 14)) ^ ((int)((uint)x >> 3));
		}

		private int Theta1(int x)
		{
			return (((int)((uint)x >> 17)) | (x << 15)) ^ (((int)((uint)x >> 19)) | (x << 13)) ^ ((int)((uint)x >> 10));
		}

		/* SHA-256 Constants
		 * (represent the first 32 bits of the fractional parts of the
		 * cube roots of the first sixty-four prime numbers)
		 */
		internal static readonly int[] K = new int[] {0x428a2f98, 0x71374491, unchecked((int)0xb5c0fbcf), unchecked((int)0xe9b5dba5), 0x3956c25b, 0x59f111f1, unchecked((int)0x923f82a4), unchecked((int)0xab1c5ed5), unchecked((int)0xd807aa98), 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, unchecked((int)0x80deb1fe), unchecked((int)0x9bdc06a7), unchecked((int)0xc19bf174), unchecked((int)0xe49b69c1), unchecked((int)0xefbe4786), 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, unchecked((int)0x983e5152), unchecked((int)0xa831c66d), unchecked((int)0xb00327c8), unchecked((int)0xbf597fc7), unchecked((int)0xc6e00bf3), unchecked((int)0xd5a79147), 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, unchecked((int)0x81c2c92e), unchecked((int)0x92722c85), unchecked((int)0xa2bfe8a1), unchecked((int)0xa81a664b), unchecked((int)0xc24b8b70), unchecked((int)0xc76c51a3), unchecked((int)0xd192e819), unchecked((int)0xd6990624), unchecked((int)0xf40e3585), 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, unchecked((int)0x84c87814), unchecked((int)0x8cc70208), unchecked((int)0x90befffa), unchecked((int)0xa4506ceb), unchecked((int)0xbef9a3f7), unchecked((int)0xc67178f2)};

		public override Memoable copy()
		{
			return new SHA256Digest(this);
		}

		public override void reset(Memoable other)
		{
			SHA256Digest d = (SHA256Digest)other;

			copyIn(d);
		}

		public virtual byte[] getEncodedState()
		{
			byte[] state = new byte[52 + xOff * 4];

			base.populateState(state);

			Pack.intToBigEndian(H1, state, 16);
			Pack.intToBigEndian(H2, state, 20);
			Pack.intToBigEndian(H3, state, 24);
			Pack.intToBigEndian(H4, state, 28);
			Pack.intToBigEndian(H5, state, 32);
			Pack.intToBigEndian(H6, state, 36);
			Pack.intToBigEndian(H7, state, 40);
			Pack.intToBigEndian(H8, state, 44);
			Pack.intToBigEndian(xOff, state, 48);

			for (int i = 0; i != xOff; i++)
			{
				Pack.intToBigEndian(X[i], state, 52 + (i * 4));
			}

			return state;
		}
	}


}