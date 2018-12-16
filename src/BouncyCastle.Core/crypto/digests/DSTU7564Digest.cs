using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.digests
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Memoable = org.bouncycastle.util.Memoable;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// Reference implementation of national ukrainian standard of hashing transformation DSTU7564.
	/// Thanks to Roman Oliynykov' native C implementation:
	/// https://github.com/Roman-Oliynykov/Kupyna-reference
	/// </summary>
	public class DSTU7564Digest : ExtendedDigest, Memoable
	{
		/* Number of 8-byte words in operating state for <= 256-bit hash codes */
		private const int NB_512 = 8;

		/* Number of 8-byte words in operating state for <= 512-bit hash codes */
		private const int NB_1024 = 16;

		/* Number of rounds for 512-bit state */
		private const int NR_512 = 10;

		/* Number of rounds for 1024-bit state */
		private const int NR_1024 = 14;

		private int hashSize;
		private int blockSize;

		private int columns;
		private int rounds;

		private ulong[] state;
		private ulong[] tempState1;
		private ulong[] tempState2;

		// TODO Guard against 'inputBlocks' overflow (2^64 blocks)
		private ulong inputBlocks;
		private int bufOff;
		private byte[] buf;

		public DSTU7564Digest(DSTU7564Digest digest)
		{
			copyIn(digest);
		}

		private void copyIn(DSTU7564Digest digest)
		{
			this.hashSize = digest.hashSize;
			this.blockSize = digest.blockSize;

			this.rounds = digest.rounds;
			if (columns > 0 && columns == digest.columns)
			{
				JavaSystem.arraycopy(digest.state, 0, state, 0, columns);
				JavaSystem.arraycopy(digest.buf, 0, buf, 0, blockSize);
			}
			else
			{
				this.columns = digest.columns;
				this.state = Arrays.clone(digest.state);
				this.tempState1 = new ulong[columns];
				this.tempState2 = new ulong[columns];
				this.buf = Arrays.clone(digest.buf);
			}

			this.inputBlocks = digest.inputBlocks;
			this.bufOff = digest.bufOff;
		}

		public DSTU7564Digest(int hashSizeBits)
		{
			if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512)
			{
				this.hashSize = (int)((uint)hashSizeBits >> 3);
			}
			else
			{
				throw new IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead");
			}

			if (hashSizeBits > 256)
			{
				this.columns = NB_1024;
				this.rounds = NR_1024;
			}
			else
			{
				this.columns = NB_512;
				this.rounds = NR_512;
			}

			this.blockSize = columns << 3;

			this.state = new ulong[columns];
			this.state[0] = (ulong)blockSize;

			this.tempState1 = new ulong[columns];
			this.tempState2 = new ulong[columns];

			this.buf = new byte[blockSize];
		}

		public virtual string getAlgorithmName()
		{
			return "DSTU7564";
		}

		public virtual int getDigestSize()
		{
			return hashSize;
		}

		public virtual int getByteLength()
		{
			return blockSize;
		}

		public virtual void update(byte @in)
		{
			buf[bufOff++] = @in;
			if (bufOff == blockSize)
			{
				processBlock(buf, 0);
				bufOff = 0;
				++inputBlocks;
			}
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			while (bufOff != 0 && len > 0)
			{
				update(@in[inOff++]);
				--len;
			}

			if (len > 0)
			{
				while (len >= blockSize)
				{
					processBlock(@in, inOff);
					inOff += blockSize;
					len -= blockSize;
					++inputBlocks;
				}

				while (len > 0)
				{
					update(@in[inOff++]);
					--len;
				}
			}
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			{
			// Apply padding: terminator byte and 96-bit length field
				int inputBytes = bufOff;
				buf[bufOff++] = unchecked((byte)0x80);

				int lenPos = blockSize - 12;
				if (bufOff > lenPos)
				{
					while (bufOff < blockSize)
					{
						buf[bufOff++] = 0;
					}
					bufOff = 0;
					processBlock(buf, 0);
				}

				while (bufOff < lenPos)
				{
					buf[bufOff++] = 0;
				}

				ulong c = ((inputBlocks & 0xFFFFFFFFL) * (ulong)blockSize + (uint)inputBytes) << 3;
				Pack.intToLittleEndian((int)c, buf, bufOff);
				bufOff += 4;
			    c >>= 32;
			    c += ((inputBlocks >> 32) * (ulong)blockSize) << 3;
			    Pack.UlongToLittleEndian(c, buf, bufOff);
	//            bufOff += 8;
				processBlock(buf, 0);
			}

			{
				JavaSystem.arraycopy(state, 0, tempState1, 0, columns);

				P(tempState1);

				for (int col = 0; col < columns; ++col)
				{
					state[col] ^= tempState1[col];
				}
			}

			int neededColumns = (int)((uint)hashSize >> 3);
			for (int col = columns - neededColumns; col < columns; ++col)
			{
				Pack.UlongToLittleEndian(state[col], @out, outOff);
				outOff += 8;
			}

			reset();

			return hashSize;
		}

		public virtual void reset()
		{
			Arrays.fill(state, 0UL);
			state[0] = (ulong)blockSize;

			inputBlocks = 0;
			bufOff = 0;
		}

		private void processBlock(byte[] input, int inOff)
		{
			int pos = inOff;
			for (int col = 0; col < columns; ++col)
			{
				ulong word = Pack.littleEndianToULong(input, pos);
				pos += 8;

				tempState1[col] = state[col] ^ word;
				tempState2[col] = word;
			}

			P(tempState1);
			Q(tempState2);

			for (int col = 0; col < columns; ++col)
			{
				state[col] ^= tempState1[col] ^ tempState2[col];
			}
		}

		private void P(ulong[] s)
		{
			for (int round = 0; round < rounds; ++round)
			{
				ulong rc = (ulong)round;

				/* AddRoundConstants */
				for (int col = 0; col < columns; ++col)
				{
					s[col] ^= rc;
					rc += 0x10L;
				}

				shiftRows(s);
				subBytes(s);
				mixColumns(s);
			}
		}

		private void Q(ulong[] s)
		{
			for (int round = 0; round < rounds; ++round)
			{
				/* AddRoundConstantsQ */
				ulong rc = ((ulong)(((columns - 1) << 4) ^ round) << 56) | 0x00F0F0F0F0F0F0F3UL;

				for (int col = 0; col < columns; ++col)
				{
					s[col] += rc;
					rc -= 0x1000000000000000L;
				}

				shiftRows(s);
				subBytes(s);
				mixColumns(s);
			}
		}

		private static ulong mixColumn(ulong c)
		{
            //        // Calculate column multiplied by powers of 'x'
            //        long x0 = c;
            //        long x1 = ((x0 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x0 & 0x8080808080808080L) >>> 7) * 0x1DL);
            //        long x2 = ((x1 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x1 & 0x8080808080808080L) >>> 7) * 0x1DL);
            //        long x3 = ((x2 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x2 & 0x8080808080808080L) >>> 7) * 0x1DL);
            //
            //        // Calculate products with circulant matrix from (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)
            //        long m0 = x0;
            //        long m1 = x0;
            //        long m2 = x0 ^ x2;
            //        long m3 = x0;
            //        long m4 = x3;
            //        long m5 = x1 ^ x2;
            //        long m6 = x0 ^ x1 ^ x2;
            //        long m7 = x2;
            //
            //        // Assemble the rotated products
            //        return m0
            //            ^ rotate(8, m1)
            //            ^ rotate(16, m2)
            //            ^ rotate(24, m3)
            //            ^ rotate(32, m4)
            //            ^ rotate(40, m5)
            //            ^ rotate(48, m6)
            //            ^ rotate(56, m7);

            // Multiply elements by 'x'
		    ulong x1 = ((c & 0x7F7F7F7F7F7F7F7FUL) << 1) ^ (((c & 0x8080808080808080UL) >> 7) * 0x1DUL);
            ulong u, v;

			u = rotate(8, c) ^ c;
			u ^= rotate(16, u);
			u ^= rotate(48, c);

			v = u ^ c ^ x1;

            // Multiply elements by 'x^2'
		    v = ((v & 0x3F3F3F3F3F3F3F3FUL) << 2) ^ (((v & 0x8080808080808080UL) >> 6) * 0x1DUL) ^ (((v & 0x4040404040404040UL) >> 6) * 0x1DUL);

            return u ^ rotate(32, v) ^ rotate(40, x1) ^ rotate(48, x1);
		}

		private void mixColumns(ulong[] s)
		{
			for (int col = 0; col < columns; ++col)
			{
				s[col] = mixColumn(s[col]);
			}
		}

	    private static ulong rotate(int n, ulong x)
	    {
	        return (x >> n) | (x << -n);
	    }

        private void shiftRows(ulong[] s)
		{
			switch (columns)
			{
			case NB_512:
			{
				ulong c0 = s[0], c1 = s[1], c2 = s[2], c3 = s[3];
				ulong c4 = s[4], c5 = s[5], c6 = s[6], c7 = s[7];
				ulong d;

				d = (c0 ^ c4) & 0xFFFFFFFF00000000UL;
				c0 ^= d;
				c4 ^= d;
				d = (c1 ^ c5) & 0x00FFFFFFFF000000UL;
				c1 ^= d;
				c5 ^= d;
				d = (c2 ^ c6) & 0x0000FFFFFFFF0000UL;
				c2 ^= d;
				c6 ^= d;
				d = (c3 ^ c7) & 0x000000FFFFFFFF00UL;
				c3 ^= d;
				c7 ^= d;

				d = (c0 ^ c2) & 0xFFFF0000FFFF0000UL;
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x00FFFF0000FFFF00UL;
				c1 ^= d;
				c3 ^= d;
				d = (c4 ^ c6) & 0xFFFF0000FFFF0000UL;
				c4 ^= d;
				c6 ^= d;
				d = (c5 ^ c7) & 0x00FFFF0000FFFF00UL;
				c5 ^= d;
				c7 ^= d;

				d = (c0 ^ c1) & 0xFF00FF00FF00FF00UL;
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & 0xFF00FF00FF00FF00UL;
				c2 ^= d;
				c3 ^= d;
				d = (c4 ^ c5) & 0xFF00FF00FF00FF00UL;
				c4 ^= d;
				c5 ^= d;
				d = (c6 ^ c7) & 0xFF00FF00FF00FF00UL;
				c6 ^= d;
				c7 ^= d;

				s[0] = c0;
				s[1] = c1;
				s[2] = c2;
				s[3] = c3;
				s[4] = c4;
				s[5] = c5;
				s[6] = c6;
				s[7] = c7;
				break;
			}
			case NB_1024:
			{
				ulong c00 = s[0], c01 = s[1], c02 = s[2], c03 = s[3];
				ulong c04 = s[4], c05 = s[5], c06 = s[6], c07 = s[7];
				ulong c08 = s[8], c09 = s[9], c10 = s[10], c11 = s[11];
				ulong c12 = s[12], c13 = s[13], c14 = s[14], c15 = s[15];
				ulong d;

				// NOTE: Row 7 is shifted by 11

				d = (c00 ^ c08) & 0xFF00000000000000UL;
				c00 ^= d;
				c08 ^= d;
				d = (c01 ^ c09) & 0xFF00000000000000UL;
				c01 ^= d;
				c09 ^= d;
				d = (c02 ^ c10) & 0xFFFF000000000000UL;
				c02 ^= d;
				c10 ^= d;
				d = (c03 ^ c11) & 0xFFFFFF0000000000UL;
				c03 ^= d;
				c11 ^= d;
				d = (c04 ^ c12) & 0xFFFFFFFF00000000UL;
				c04 ^= d;
				c12 ^= d;
				d = (c05 ^ c13) & 0x00FFFFFFFF000000UL;
				c05 ^= d;
				c13 ^= d;
				d = (c06 ^ c14) & 0x00FFFFFFFFFF0000UL;
				c06 ^= d;
				c14 ^= d;
				d = (c07 ^ c15) & 0x00FFFFFFFFFFFF00UL;
				c07 ^= d;
				c15 ^= d;

				d = (c00 ^ c04) & 0x00FFFFFF00000000UL;
				c00 ^= d;
				c04 ^= d;
				d = (c01 ^ c05) & 0xFFFFFFFFFF000000UL;
				c01 ^= d;
				c05 ^= d;
				d = (c02 ^ c06) & 0xFF00FFFFFFFF0000UL;
				c02 ^= d;
				c06 ^= d;
				d = (c03 ^ c07) & 0xFF0000FFFFFFFF00UL;
				c03 ^= d;
				c07 ^= d;
			    d = (c08 ^ c12) & 0x00FFFFFF00000000UL;
				c08 ^= d;
				c12 ^= d;
				d = (c09 ^ c13) & 0xFFFFFFFFFF000000UL;
				c09 ^= d;
				c13 ^= d;
				d = (c10 ^ c14) & 0xFF00FFFFFFFF0000UL;
				c10 ^= d;
				c14 ^= d;
				d = (c11 ^ c15) & 0xFF0000FFFFFFFF00UL;
				c11 ^= d;
				c15 ^= d;

				d = (c00 ^ c02) & 0xFFFF0000FFFF0000UL;
				c00 ^= d;
				c02 ^= d;
				d = (c01 ^ c03) & 0x00FFFF0000FFFF00UL;
				c01 ^= d;
				c03 ^= d;
				d = (c04 ^ c06) & 0xFFFF0000FFFF0000UL;
				c04 ^= d;
				c06 ^= d;
				d = (c05 ^ c07) & 0x00FFFF0000FFFF00UL;
				c05 ^= d;
				c07 ^= d;
				d = (c08 ^ c10) & 0xFFFF0000FFFF0000UL;
				c08 ^= d;
				c10 ^= d;
				d = (c09 ^ c11) & 0x00FFFF0000FFFF00UL;
				c09 ^= d;
				c11 ^= d;
				d = (c12 ^ c14) & 0xFFFF0000FFFF0000UL;
				c12 ^= d;
				c14 ^= d;
				d = (c13 ^ c15) & 0x00FFFF0000FFFF00L;
				c13 ^= d;
				c15 ^= d;

				d = (c00 ^ c01) & 0xFF00FF00FF00FF00UL;
				c00 ^= d;
				c01 ^= d;
				d = (c02 ^ c03) & 0xFF00FF00FF00FF00UL;
				c02 ^= d;
				c03 ^= d;
				d = (c04 ^ c05) & 0xFF00FF00FF00FF00UL;
				c04 ^= d;
				c05 ^= d;
				d = (c06 ^ c07) & 0xFF00FF00FF00FF00UL;
				c06 ^= d;
				c07 ^= d;
				d = (c08 ^ c09) & 0xFF00FF00FF00FF00UL;
				c08 ^= d;
				c09 ^= d;
				d = (c10 ^ c11) & 0xFF00FF00FF00FF00UL;
				c10 ^= d;
				c11 ^= d;
				d = (c12 ^ c13) & 0xFF00FF00FF00FF00UL;
				c12 ^= d;
				c13 ^= d;
				d = (c14 ^ c15) & 0xFF00FF00FF00FF00UL;
				c14 ^= d;
				c15 ^= d;

				s[0] = c00;
				s[1] = c01;
				s[2] = c02;
				s[3] = c03;
				s[4] = c04;
				s[5] = c05;
				s[6] = c06;
				s[7] = c07;
				s[8] = c08;
				s[9] = c09;
				s[10] = c10;
				s[11] = c11;
				s[12] = c12;
				s[13] = c13;
				s[14] = c14;
				s[15] = c15;
				break;
			}
			default:
			{
				throw new IllegalStateException("unsupported state size: only 512/1024 are allowed");
			}
			}
		}

	    private void subBytes(ulong[] s)
	    {
	        for (int i = 0; i < columns; ++i)
	        {
	            ulong u = s[i];
	            uint lo = (uint)u, hi = (uint)(u >> 32);
	            byte t0 = S0[lo & 0xFF];
	            byte t1 = S1[(lo >> 8) & 0xFF];
	            byte t2 = S2[(lo >> 16) & 0xFF];
	            byte t3 = S3[lo >> 24];
	            lo = (uint)t0 | ((uint)t1 << 8) | ((uint)t2 << 16) | ((uint)t3 << 24);
	            byte t4 = S0[hi & 0xFF];
	            byte t5 = S1[(hi >> 8) & 0xFF];
	            byte t6 = S2[(hi >> 16) & 0xFF];
	            byte t7 = S3[hi >> 24];
	            hi = (uint)t4 | ((uint)t5 << 8) | ((uint)t6 << 16) | ((uint)t7 << 24);
	            s[i] = (ulong)lo | ((ulong)hi << 32);
	        }
	    }

        private static readonly byte[] S0 = new byte[]{unchecked((byte)0xa8), (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75, (byte)0x6c, (byte)0x59, (byte)0x71, unchecked((byte)0xdf), unchecked((byte)0x87), unchecked((byte)0x95), (byte)0x17, unchecked((byte)0xf0), unchecked((byte)0xd8), (byte)0x09, (byte)0x6d, unchecked((byte)0xf3), (byte)0x1d, unchecked((byte)0xcb), unchecked((byte)0xc9), (byte)0x4d, (byte)0x2c, unchecked((byte)0xaf), (byte)0x79, unchecked((byte)0xe0), unchecked((byte)0x97), unchecked((byte)0xfd), (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39, (byte)0x3e, unchecked((byte)0xdd), unchecked((byte)0xa3), (byte)0x4f, unchecked((byte)0xb4), unchecked((byte)0xb6), unchecked((byte)0x9a), (byte)0x0e, (byte)0x1f, unchecked((byte)0xbf), (byte)0x15, unchecked((byte)0xe1), (byte)0x49, unchecked((byte)0xd2), unchecked((byte)0x93), unchecked((byte)0xc6), unchecked((byte)0x92), (byte)0x72, unchecked((byte)0x9e), (byte)0x61, unchecked((byte)0xd1), (byte)0x63, unchecked((byte)0xfa), unchecked((byte)0xee), unchecked((byte)0xf4), (byte)0x19, unchecked((byte)0xd5), unchecked((byte)0xad), (byte)0x58, unchecked((byte)0xa4), unchecked((byte)0xbb), unchecked((byte)0xa1), unchecked((byte)0xdc), unchecked((byte)0xf2), unchecked((byte)0x83), (byte)0x37, (byte)0x42, unchecked((byte)0xe4), (byte)0x7a, (byte)0x32, unchecked((byte)0x9c), unchecked((byte)0xcc), unchecked((byte)0xab), (byte)0x4a, unchecked((byte)0x8f), (byte)0x6e, (byte)0x04, (byte)0x27, (byte)0x2e, unchecked((byte)0xe7), unchecked((byte)0xe2), (byte)0x5a, unchecked((byte)0x96), (byte)0x16, (byte)0x23, (byte)0x2b, unchecked((byte)0xc2), (byte)0x65, (byte)0x66, (byte)0x0f, unchecked((byte)0xbc), unchecked((byte)0xa9), (byte)0x47, (byte)0x41, (byte)0x34, (byte)0x48, unchecked((byte)0xfc), unchecked((byte)0xb7), (byte)0x6a, unchecked((byte)0x88), unchecked((byte)0xa5), (byte)0x53, unchecked((byte)0x86), unchecked((byte)0xf9), (byte)0x5b, unchecked((byte)0xdb), (byte)0x38, (byte)0x7b, unchecked((byte)0xc3), (byte)0x1e, (byte)0x22, (byte)0x33, (byte)0x24, (byte)0x28, (byte)0x36, unchecked((byte)0xc7), unchecked((byte)0xb2), (byte)0x3b, unchecked((byte)0x8e), (byte)0x77, unchecked((byte)0xba), unchecked((byte)0xf5), (byte)0x14, unchecked((byte)0x9f), (byte)0x08, (byte)0x55, unchecked((byte)0x9b), (byte)0x4c, unchecked((byte)0xfe), (byte)0x60, (byte)0x5c, unchecked((byte)0xda), (byte)0x18, (byte)0x46, unchecked((byte)0xcd), (byte)0x7d, (byte)0x21, unchecked((byte)0xb0), (byte)0x3f, (byte)0x1b, unchecked((byte)0x89), unchecked((byte)0xff), unchecked((byte)0xeb), unchecked((byte)0x84), (byte)0x69, (byte)0x3a, unchecked((byte)0x9d), unchecked((byte)0xd7), unchecked((byte)0xd3), (byte)0x70, (byte)0x67, (byte)0x40, unchecked((byte)0xb5), unchecked((byte)0xde), (byte)0x5d, (byte)0x30, unchecked((byte)0x91), unchecked((byte)0xb1), (byte)0x78, (byte)0x11, (byte)0x01, unchecked((byte)0xe5), (byte)0x00, (byte)0x68, unchecked((byte)0x98), unchecked((byte)0xa0), unchecked((byte)0xc5), (byte)0x02, unchecked((byte)0xa6), (byte)0x74, (byte)0x2d, (byte)0x0b, unchecked((byte)0xa2), (byte)0x76, unchecked((byte)0xb3), unchecked((byte)0xbe), unchecked((byte)0xce), unchecked((byte)0xbd), unchecked((byte)0xae), unchecked((byte)0xe9), unchecked((byte)0x8a), (byte)0x31, (byte)0x1c, unchecked((byte)0xec), unchecked((byte)0xf1), unchecked((byte)0x99), unchecked((byte)0x94), unchecked((byte)0xaa), unchecked((byte)0xf6), (byte)0x26, (byte)0x2f, unchecked((byte)0xef), unchecked((byte)0xe8), unchecked((byte)0x8c), (byte)0x35, (byte)0x03, unchecked((byte)0xd4), (byte)0x7f, unchecked((byte)0xfb), (byte)0x05, unchecked((byte)0xc1), (byte)0x5e, unchecked((byte)0x90), (byte)0x20, (byte)0x3d, unchecked((byte)0x82), unchecked((byte)0xf7), unchecked((byte)0xea), (byte)0x0a, (byte)0x0d, (byte)0x7e, unchecked((byte)0xf8), (byte)0x50, (byte)0x1a, unchecked((byte)0xc4), (byte)0x07, (byte)0x57, unchecked((byte)0xb8), (byte)0x3c, (byte)0x62, unchecked((byte)0xe3), unchecked((byte)0xc8), unchecked((byte)0xac), (byte)0x52, (byte)0x64, (byte)0x10, unchecked((byte)0xd0), unchecked((byte)0xd9), (byte)0x13, (byte)0x0c, (byte)0x12, (byte)0x29, (byte)0x51, unchecked((byte)0xb9), unchecked((byte)0xcf), unchecked((byte)0xd6), (byte)0x73, unchecked((byte)0x8d), unchecked((byte)0x81), (byte)0x54, unchecked((byte)0xc0), unchecked((byte)0xed), (byte)0x4e, (byte)0x44, unchecked((byte)0xa7), (byte)0x2a, unchecked((byte)0x85), (byte)0x25, unchecked((byte)0xe6), unchecked((byte)0xca), (byte)0x7c, unchecked((byte)0x8b), (byte)0x56, unchecked((byte)0x80)};

		private static readonly byte[] S1 = new byte[]{unchecked((byte)0xce), unchecked((byte)0xbb), unchecked((byte)0xeb), unchecked((byte)0x92), unchecked((byte)0xea), unchecked((byte)0xcb), (byte)0x13, unchecked((byte)0xc1), unchecked((byte)0xe9), (byte)0x3a, unchecked((byte)0xd6), unchecked((byte)0xb2), unchecked((byte)0xd2), unchecked((byte)0x90), (byte)0x17, unchecked((byte)0xf8), (byte)0x42, (byte)0x15, (byte)0x56, unchecked((byte)0xb4), (byte)0x65, (byte)0x1c, unchecked((byte)0x88), (byte)0x43, unchecked((byte)0xc5), (byte)0x5c, (byte)0x36, unchecked((byte)0xba), unchecked((byte)0xf5), (byte)0x57, (byte)0x67, unchecked((byte)0x8d), (byte)0x31, unchecked((byte)0xf6), (byte)0x64, (byte)0x58, unchecked((byte)0x9e), unchecked((byte)0xf4), (byte)0x22, unchecked((byte)0xaa), (byte)0x75, (byte)0x0f, (byte)0x02, unchecked((byte)0xb1), unchecked((byte)0xdf), (byte)0x6d, (byte)0x73, (byte)0x4d, (byte)0x7c, (byte)0x26, (byte)0x2e, unchecked((byte)0xf7), (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e, unchecked((byte)0x9f), (byte)0x14, unchecked((byte)0xc8), unchecked((byte)0xae), (byte)0x54, (byte)0x10, unchecked((byte)0xd8), unchecked((byte)0xbc), (byte)0x1a, (byte)0x6b, (byte)0x69, unchecked((byte)0xf3), unchecked((byte)0xbd), (byte)0x33, unchecked((byte)0xab), unchecked((byte)0xfa), unchecked((byte)0xd1), unchecked((byte)0x9b), (byte)0x68, (byte)0x4e, (byte)0x16, unchecked((byte)0x95), unchecked((byte)0x91), unchecked((byte)0xee), (byte)0x4c, (byte)0x63, unchecked((byte)0x8e), (byte)0x5b, unchecked((byte)0xcc), (byte)0x3c, (byte)0x19, unchecked((byte)0xa1), unchecked((byte)0x81), (byte)0x49, (byte)0x7b, unchecked((byte)0xd9), (byte)0x6f, (byte)0x37, (byte)0x60, unchecked((byte)0xca), unchecked((byte)0xe7), (byte)0x2b, (byte)0x48, unchecked((byte)0xfd), unchecked((byte)0x96), (byte)0x45, unchecked((byte)0xfc), (byte)0x41, (byte)0x12, (byte)0x0d, (byte)0x79, unchecked((byte)0xe5), unchecked((byte)0x89), unchecked((byte)0x8c), unchecked((byte)0xe3), (byte)0x20, (byte)0x30, unchecked((byte)0xdc), unchecked((byte)0xb7), (byte)0x6c, (byte)0x4a, unchecked((byte)0xb5), (byte)0x3f, unchecked((byte)0x97), unchecked((byte)0xd4), (byte)0x62, (byte)0x2d, (byte)0x06, unchecked((byte)0xa4), unchecked((byte)0xa5), unchecked((byte)0x83), (byte)0x5f, (byte)0x2a, unchecked((byte)0xda), unchecked((byte)0xc9), (byte)0x00, (byte)0x7e, unchecked((byte)0xa2), (byte)0x55, unchecked((byte)0xbf), (byte)0x11, unchecked((byte)0xd5), unchecked((byte)0x9c), unchecked((byte)0xcf), (byte)0x0e, (byte)0x0a, (byte)0x3d, (byte)0x51, (byte)0x7d, unchecked((byte)0x93), (byte)0x1b, unchecked((byte)0xfe), unchecked((byte)0xc4), (byte)0x47, (byte)0x09, unchecked((byte)0x86), (byte)0x0b, unchecked((byte)0x8f), unchecked((byte)0x9d), (byte)0x6a, (byte)0x07, unchecked((byte)0xb9), unchecked((byte)0xb0), unchecked((byte)0x98), (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, unchecked((byte)0xef), (byte)0x3b, (byte)0x70, unchecked((byte)0xa0), unchecked((byte)0xe4), (byte)0x40, unchecked((byte)0xff), unchecked((byte)0xc3), unchecked((byte)0xa9), unchecked((byte)0xe6), (byte)0x78, unchecked((byte)0xf9), unchecked((byte)0x8b), (byte)0x46, unchecked((byte)0x80), (byte)0x1e, (byte)0x38, unchecked((byte)0xe1), unchecked((byte)0xb8), unchecked((byte)0xa8), unchecked((byte)0xe0), (byte)0x0c, (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05, unchecked((byte)0xf1), (byte)0x6e, unchecked((byte)0x94), (byte)0x28, unchecked((byte)0x9a), unchecked((byte)0x84), unchecked((byte)0xe8), unchecked((byte)0xa3), (byte)0x4f, (byte)0x77, unchecked((byte)0xd3), unchecked((byte)0x85), unchecked((byte)0xe2), (byte)0x52, unchecked((byte)0xf2), unchecked((byte)0x82), (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53, unchecked((byte)0xb3), (byte)0x61, unchecked((byte)0xaf), (byte)0x39, (byte)0x35, unchecked((byte)0xde), unchecked((byte)0xcd), (byte)0x1f, unchecked((byte)0x99), unchecked((byte)0xac), unchecked((byte)0xad), (byte)0x72, (byte)0x2c, unchecked((byte)0xdd), unchecked((byte)0xd0), unchecked((byte)0x87), unchecked((byte)0xbe), (byte)0x5e, unchecked((byte)0xa6), unchecked((byte)0xec), (byte)0x04, unchecked((byte)0xc6), (byte)0x03, (byte)0x34, unchecked((byte)0xfb), unchecked((byte)0xdb), (byte)0x59, unchecked((byte)0xb6), unchecked((byte)0xc2), (byte)0x01, unchecked((byte)0xf0), (byte)0x5a, unchecked((byte)0xed), unchecked((byte)0xa7), (byte)0x66, (byte)0x21, (byte)0x7f, unchecked((byte)0x8a), (byte)0x27, unchecked((byte)0xc7), unchecked((byte)0xc0), (byte)0x29, unchecked((byte)0xd7)};

		private static readonly byte[] S2 = new byte[]{unchecked((byte)0x93), unchecked((byte)0xd9), unchecked((byte)0x9a), unchecked((byte)0xb5), unchecked((byte)0x98), (byte)0x22, (byte)0x45, unchecked((byte)0xfc), unchecked((byte)0xba), (byte)0x6a, unchecked((byte)0xdf), (byte)0x02, unchecked((byte)0x9f), unchecked((byte)0xdc), (byte)0x51, (byte)0x59, (byte)0x4a, (byte)0x17, (byte)0x2b, unchecked((byte)0xc2), unchecked((byte)0x94), unchecked((byte)0xf4), unchecked((byte)0xbb), unchecked((byte)0xa3), (byte)0x62, unchecked((byte)0xe4), (byte)0x71, unchecked((byte)0xd4), unchecked((byte)0xcd), (byte)0x70, (byte)0x16, unchecked((byte)0xe1), (byte)0x49, (byte)0x3c, unchecked((byte)0xc0), unchecked((byte)0xd8), (byte)0x5c, unchecked((byte)0x9b), unchecked((byte)0xad), unchecked((byte)0x85), (byte)0x53, unchecked((byte)0xa1), (byte)0x7a, unchecked((byte)0xc8), (byte)0x2d, unchecked((byte)0xe0), unchecked((byte)0xd1), (byte)0x72, unchecked((byte)0xa6), (byte)0x2c, unchecked((byte)0xc4), unchecked((byte)0xe3), (byte)0x76, (byte)0x78, unchecked((byte)0xb7), unchecked((byte)0xb4), (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41, (byte)0x4c, unchecked((byte)0xde), unchecked((byte)0xb2), unchecked((byte)0x90), (byte)0x25, unchecked((byte)0xa5), unchecked((byte)0xd7), (byte)0x03, (byte)0x11, (byte)0x00, unchecked((byte)0xc3), (byte)0x2e, unchecked((byte)0x92), unchecked((byte)0xef), (byte)0x4e, (byte)0x12, unchecked((byte)0x9d), (byte)0x7d, unchecked((byte)0xcb), (byte)0x35, (byte)0x10, unchecked((byte)0xd5), (byte)0x4f, unchecked((byte)0x9e), (byte)0x4d, unchecked((byte)0xa9), (byte)0x55, unchecked((byte)0xc6), unchecked((byte)0xd0), (byte)0x7b, (byte)0x18, unchecked((byte)0x97), unchecked((byte)0xd3), (byte)0x36, unchecked((byte)0xe6), (byte)0x48, (byte)0x56, unchecked((byte)0x81), unchecked((byte)0x8f), (byte)0x77, unchecked((byte)0xcc), unchecked((byte)0x9c), unchecked((byte)0xb9), unchecked((byte)0xe2), unchecked((byte)0xac), unchecked((byte)0xb8), (byte)0x2f, (byte)0x15, unchecked((byte)0xa4), (byte)0x7c, unchecked((byte)0xda), (byte)0x38, (byte)0x1e, (byte)0x0b, (byte)0x05, unchecked((byte)0xd6), (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, unchecked((byte)0xfd), unchecked((byte)0xb1), unchecked((byte)0xe5), (byte)0x60, unchecked((byte)0xaf), (byte)0x5e, (byte)0x33, unchecked((byte)0x87), unchecked((byte)0xc9), unchecked((byte)0xf0), (byte)0x5d, (byte)0x6d, (byte)0x3f, unchecked((byte)0x88), unchecked((byte)0x8d), unchecked((byte)0xc7), unchecked((byte)0xf7), (byte)0x1d, unchecked((byte)0xe9), unchecked((byte)0xec), unchecked((byte)0xed), unchecked((byte)0x80), (byte)0x29, (byte)0x27, unchecked((byte)0xcf), unchecked((byte)0x99), unchecked((byte)0xa8), (byte)0x50, (byte)0x0f, (byte)0x37, (byte)0x24, (byte)0x28, (byte)0x30, unchecked((byte)0x95), unchecked((byte)0xd2), (byte)0x3e, (byte)0x5b, (byte)0x40, unchecked((byte)0x83), unchecked((byte)0xb3), (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, unchecked((byte)0x8a), unchecked((byte)0xbc), (byte)0x20, unchecked((byte)0xeb), unchecked((byte)0xce), unchecked((byte)0x8e), unchecked((byte)0xab), unchecked((byte)0xee), (byte)0x31, unchecked((byte)0xa2), (byte)0x73, unchecked((byte)0xf9), unchecked((byte)0xca), (byte)0x3a, (byte)0x1a, unchecked((byte)0xfb), (byte)0x0d, unchecked((byte)0xc1), unchecked((byte)0xfe), unchecked((byte)0xfa), unchecked((byte)0xf2), (byte)0x6f, unchecked((byte)0xbd), unchecked((byte)0x96), unchecked((byte)0xdd), (byte)0x43, (byte)0x52, unchecked((byte)0xb6), (byte)0x08, unchecked((byte)0xf3), unchecked((byte)0xae), unchecked((byte)0xbe), (byte)0x19, unchecked((byte)0x89), (byte)0x32, (byte)0x26, unchecked((byte)0xb0), unchecked((byte)0xea), (byte)0x4b, (byte)0x64, unchecked((byte)0x84), unchecked((byte)0x82), (byte)0x6b, unchecked((byte)0xf5), (byte)0x79, unchecked((byte)0xbf), (byte)0x01, (byte)0x5f, (byte)0x75, (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65, unchecked((byte)0xe8), unchecked((byte)0x91), unchecked((byte)0xf6), unchecked((byte)0xff), (byte)0x13, (byte)0x58, unchecked((byte)0xf1), (byte)0x47, (byte)0x0a, (byte)0x7f, unchecked((byte)0xc5), unchecked((byte)0xa7), unchecked((byte)0xe7), (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44, (byte)0x42, (byte)0x04, unchecked((byte)0xa0), unchecked((byte)0xdb), (byte)0x39, unchecked((byte)0x86), (byte)0x54, unchecked((byte)0xaa), unchecked((byte)0x8c), (byte)0x34, (byte)0x21, unchecked((byte)0x8b), unchecked((byte)0xf8), (byte)0x0c, (byte)0x74, (byte)0x67};

		private static readonly byte[] S3 = new byte[]{(byte)0x68, unchecked((byte)0x8d), unchecked((byte)0xca), (byte)0x4d, (byte)0x73, (byte)0x4b, (byte)0x4e, (byte)0x2a, unchecked((byte)0xd4), (byte)0x52, (byte)0x26, unchecked((byte)0xb3), (byte)0x54, (byte)0x1e, (byte)0x19, (byte)0x1f, (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, unchecked((byte)0x83), (byte)0x13, unchecked((byte)0x8a), unchecked((byte)0xb7), unchecked((byte)0xd5), (byte)0x25, (byte)0x79, unchecked((byte)0xf5), unchecked((byte)0xbd), (byte)0x58, (byte)0x2f, (byte)0x0d, (byte)0x02, unchecked((byte)0xed), (byte)0x51, unchecked((byte)0x9e), (byte)0x11, unchecked((byte)0xf2), (byte)0x3e, (byte)0x55, (byte)0x5e, unchecked((byte)0xd1), (byte)0x16, (byte)0x3c, (byte)0x66, (byte)0x70, (byte)0x5d, unchecked((byte)0xf3), (byte)0x45, (byte)0x40, unchecked((byte)0xcc), unchecked((byte)0xe8), unchecked((byte)0x94), (byte)0x56, (byte)0x08, unchecked((byte)0xce), (byte)0x1a, (byte)0x3a, unchecked((byte)0xd2), unchecked((byte)0xe1), unchecked((byte)0xdf), unchecked((byte)0xb5), (byte)0x38, (byte)0x6e, (byte)0x0e, unchecked((byte)0xe5), unchecked((byte)0xf4), unchecked((byte)0xf9), unchecked((byte)0x86), unchecked((byte)0xe9), (byte)0x4f, unchecked((byte)0xd6), unchecked((byte)0x85), (byte)0x23, unchecked((byte)0xcf), (byte)0x32, unchecked((byte)0x99), (byte)0x31, (byte)0x14, unchecked((byte)0xae), unchecked((byte)0xee), unchecked((byte)0xc8), (byte)0x48, unchecked((byte)0xd3), (byte)0x30, unchecked((byte)0xa1), unchecked((byte)0x92), (byte)0x41, unchecked((byte)0xb1), (byte)0x18, unchecked((byte)0xc4), (byte)0x2c, (byte)0x71, (byte)0x72, (byte)0x44, (byte)0x15, unchecked((byte)0xfd), (byte)0x37, unchecked((byte)0xbe), (byte)0x5f, unchecked((byte)0xaa), unchecked((byte)0x9b), unchecked((byte)0x88), unchecked((byte)0xd8), unchecked((byte)0xab), unchecked((byte)0x89), unchecked((byte)0x9c), unchecked((byte)0xfa), (byte)0x60, unchecked((byte)0xea), unchecked((byte)0xbc), (byte)0x62, (byte)0x0c, (byte)0x24, unchecked((byte)0xa6), unchecked((byte)0xa8), unchecked((byte)0xec), (byte)0x67, (byte)0x20, unchecked((byte)0xdb), (byte)0x7c, (byte)0x28, unchecked((byte)0xdd), unchecked((byte)0xac), (byte)0x5b, (byte)0x34, (byte)0x7e, (byte)0x10, unchecked((byte)0xf1), (byte)0x7b, unchecked((byte)0x8f), (byte)0x63, unchecked((byte)0xa0), (byte)0x05, unchecked((byte)0x9a), (byte)0x43, (byte)0x77, (byte)0x21, unchecked((byte)0xbf), (byte)0x27, (byte)0x09, unchecked((byte)0xc3), unchecked((byte)0x9f), unchecked((byte)0xb6), unchecked((byte)0xd7), (byte)0x29, unchecked((byte)0xc2), unchecked((byte)0xeb), unchecked((byte)0xc0), unchecked((byte)0xa4), unchecked((byte)0x8b), unchecked((byte)0x8c), (byte)0x1d, unchecked((byte)0xfb), unchecked((byte)0xff), unchecked((byte)0xc1), unchecked((byte)0xb2), unchecked((byte)0x97), (byte)0x2e, unchecked((byte)0xf8), (byte)0x65, unchecked((byte)0xf6), (byte)0x75, (byte)0x07, (byte)0x04, (byte)0x49, (byte)0x33, unchecked((byte)0xe4), unchecked((byte)0xd9), unchecked((byte)0xb9), unchecked((byte)0xd0), (byte)0x42, unchecked((byte)0xc7), (byte)0x6c, unchecked((byte)0x90), (byte)0x00, unchecked((byte)0x8e), (byte)0x6f, (byte)0x50, (byte)0x01, unchecked((byte)0xc5), unchecked((byte)0xda), (byte)0x47, (byte)0x3f, unchecked((byte)0xcd), (byte)0x69, unchecked((byte)0xa2), unchecked((byte)0xe2), (byte)0x7a, unchecked((byte)0xa7), unchecked((byte)0xc6), unchecked((byte)0x93), (byte)0x0f, (byte)0x0a, (byte)0x06, unchecked((byte)0xe6), (byte)0x2b, unchecked((byte)0x96), unchecked((byte)0xa3), (byte)0x1c, unchecked((byte)0xaf), (byte)0x6a, (byte)0x12, unchecked((byte)0x84), (byte)0x39, unchecked((byte)0xe7), unchecked((byte)0xb0), unchecked((byte)0x82), unchecked((byte)0xf7), unchecked((byte)0xfe), unchecked((byte)0x9d), unchecked((byte)0x87), (byte)0x5c, unchecked((byte)0x81), (byte)0x35, unchecked((byte)0xde), unchecked((byte)0xb4), unchecked((byte)0xa5), unchecked((byte)0xfc), unchecked((byte)0x80), unchecked((byte)0xef), unchecked((byte)0xcb), unchecked((byte)0xbb), (byte)0x6b, (byte)0x76, unchecked((byte)0xba), (byte)0x5a, (byte)0x7d, (byte)0x78, (byte)0x0b, unchecked((byte)0x95), unchecked((byte)0xe3), unchecked((byte)0xad), (byte)0x74, unchecked((byte)0x98), (byte)0x3b, (byte)0x36, (byte)0x64, (byte)0x6d, unchecked((byte)0xdc), unchecked((byte)0xf0), (byte)0x59, unchecked((byte)0xa9), (byte)0x4c, (byte)0x17, (byte)0x7f, unchecked((byte)0x91), unchecked((byte)0xb8), unchecked((byte)0xc9), (byte)0x57, (byte)0x1b, unchecked((byte)0xe0), (byte)0x61};

		public virtual Memoable copy()
		{
			return new DSTU7564Digest(this);
		}

		public virtual void reset(Memoable other)
		{
			DSTU7564Digest d = (DSTU7564Digest)other;

			copyIn(d);
		}
	}

}