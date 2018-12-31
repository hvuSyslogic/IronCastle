using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{
			
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
				buf[bufOff++] = unchecked(0x80);

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
			    Pack.ulongToLittleEndian(c, buf, bufOff);
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
				Pack.ulongToLittleEndian(state[col], @out, outOff);
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
	            lo = t0 | ((uint)t1 << 8) | ((uint)t2 << 16) | ((uint)t3 << 24);
	            byte t4 = S0[hi & 0xFF];
	            byte t5 = S1[(hi >> 8) & 0xFF];
	            byte t6 = S2[(hi >> 16) & 0xFF];
	            byte t7 = S3[hi >> 24];
	            hi = t4 | ((uint)t5 << 8) | ((uint)t6 << 16) | ((uint)t7 << 24);
	            s[i] = lo | ((ulong)hi << 32);
	        }
	    }

        private static readonly byte[] S0 = new byte[]{unchecked(0xa8), 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, unchecked(0xdf), unchecked(0x87), unchecked(0x95), 0x17, unchecked(0xf0), unchecked(0xd8), 0x09, 0x6d, unchecked(0xf3), 0x1d, unchecked(0xcb), unchecked(0xc9), 0x4d, 0x2c, unchecked(0xaf), 0x79, unchecked(0xe0), unchecked(0x97), unchecked(0xfd), 0x6f, 0x4b, 0x45, 0x39, 0x3e, unchecked(0xdd), unchecked(0xa3), 0x4f, unchecked(0xb4), unchecked(0xb6), unchecked(0x9a), 0x0e, 0x1f, unchecked(0xbf), 0x15, unchecked(0xe1), 0x49, unchecked(0xd2), unchecked(0x93), unchecked(0xc6), unchecked(0x92), 0x72, unchecked(0x9e), 0x61, unchecked(0xd1), 0x63, unchecked(0xfa), unchecked(0xee), unchecked(0xf4), 0x19, unchecked(0xd5), unchecked(0xad), 0x58, unchecked(0xa4), unchecked(0xbb), unchecked(0xa1), unchecked(0xdc), unchecked(0xf2), unchecked(0x83), 0x37, 0x42, unchecked(0xe4), 0x7a, 0x32, unchecked(0x9c), unchecked(0xcc), unchecked(0xab), 0x4a, unchecked(0x8f), 0x6e, 0x04, 0x27, 0x2e, unchecked(0xe7), unchecked(0xe2), 0x5a, unchecked(0x96), 0x16, 0x23, 0x2b, unchecked(0xc2), 0x65, 0x66, 0x0f, unchecked(0xbc), unchecked(0xa9), 0x47, 0x41, 0x34, 0x48, unchecked(0xfc), unchecked(0xb7), 0x6a, unchecked(0x88), unchecked(0xa5), 0x53, unchecked(0x86), unchecked(0xf9), 0x5b, unchecked(0xdb), 0x38, 0x7b, unchecked(0xc3), 0x1e, 0x22, 0x33, 0x24, 0x28, 0x36, unchecked(0xc7), unchecked(0xb2), 0x3b, unchecked(0x8e), 0x77, unchecked(0xba), unchecked(0xf5), 0x14, unchecked(0x9f), 0x08, 0x55, unchecked(0x9b), 0x4c, unchecked(0xfe), 0x60, 0x5c, unchecked(0xda), 0x18, 0x46, unchecked(0xcd), 0x7d, 0x21, unchecked(0xb0), 0x3f, 0x1b, unchecked(0x89), unchecked(0xff), unchecked(0xeb), unchecked(0x84), 0x69, 0x3a, unchecked(0x9d), unchecked(0xd7), unchecked(0xd3), 0x70, 0x67, 0x40, unchecked(0xb5), unchecked(0xde), 0x5d, 0x30, unchecked(0x91), unchecked(0xb1), 0x78, 0x11, 0x01, unchecked(0xe5), 0x00, 0x68, unchecked(0x98), unchecked(0xa0), unchecked(0xc5), 0x02, unchecked(0xa6), 0x74, 0x2d, 0x0b, unchecked(0xa2), 0x76, unchecked(0xb3), unchecked(0xbe), unchecked(0xce), unchecked(0xbd), unchecked(0xae), unchecked(0xe9), unchecked(0x8a), 0x31, 0x1c, unchecked(0xec), unchecked(0xf1), unchecked(0x99), unchecked(0x94), unchecked(0xaa), unchecked(0xf6), 0x26, 0x2f, unchecked(0xef), unchecked(0xe8), unchecked(0x8c), 0x35, 0x03, unchecked(0xd4), 0x7f, unchecked(0xfb), 0x05, unchecked(0xc1), 0x5e, unchecked(0x90), 0x20, 0x3d, unchecked(0x82), unchecked(0xf7), unchecked(0xea), 0x0a, 0x0d, 0x7e, unchecked(0xf8), 0x50, 0x1a, unchecked(0xc4), 0x07, 0x57, unchecked(0xb8), 0x3c, 0x62, unchecked(0xe3), unchecked(0xc8), unchecked(0xac), 0x52, 0x64, 0x10, unchecked(0xd0), unchecked(0xd9), 0x13, 0x0c, 0x12, 0x29, 0x51, unchecked(0xb9), unchecked(0xcf), unchecked(0xd6), 0x73, unchecked(0x8d), unchecked(0x81), 0x54, unchecked(0xc0), unchecked(0xed), 0x4e, 0x44, unchecked(0xa7), 0x2a, unchecked(0x85), 0x25, unchecked(0xe6), unchecked(0xca), 0x7c, unchecked(0x8b), 0x56, unchecked(0x80)};

		private static readonly byte[] S1 = new byte[]{unchecked(0xce), unchecked(0xbb), unchecked(0xeb), unchecked(0x92), unchecked(0xea), unchecked(0xcb), 0x13, unchecked(0xc1), unchecked(0xe9), 0x3a, unchecked(0xd6), unchecked(0xb2), unchecked(0xd2), unchecked(0x90), 0x17, unchecked(0xf8), 0x42, 0x15, 0x56, unchecked(0xb4), 0x65, 0x1c, unchecked(0x88), 0x43, unchecked(0xc5), 0x5c, 0x36, unchecked(0xba), unchecked(0xf5), 0x57, 0x67, unchecked(0x8d), 0x31, unchecked(0xf6), 0x64, 0x58, unchecked(0x9e), unchecked(0xf4), 0x22, unchecked(0xaa), 0x75, 0x0f, 0x02, unchecked(0xb1), unchecked(0xdf), 0x6d, 0x73, 0x4d, 0x7c, 0x26, 0x2e, unchecked(0xf7), 0x08, 0x5d, 0x44, 0x3e, unchecked(0x9f), 0x14, unchecked(0xc8), unchecked(0xae), 0x54, 0x10, unchecked(0xd8), unchecked(0xbc), 0x1a, 0x6b, 0x69, unchecked(0xf3), unchecked(0xbd), 0x33, unchecked(0xab), unchecked(0xfa), unchecked(0xd1), unchecked(0x9b), 0x68, 0x4e, 0x16, unchecked(0x95), unchecked(0x91), unchecked(0xee), 0x4c, 0x63, unchecked(0x8e), 0x5b, unchecked(0xcc), 0x3c, 0x19, unchecked(0xa1), unchecked(0x81), 0x49, 0x7b, unchecked(0xd9), 0x6f, 0x37, 0x60, unchecked(0xca), unchecked(0xe7), 0x2b, 0x48, unchecked(0xfd), unchecked(0x96), 0x45, unchecked(0xfc), 0x41, 0x12, 0x0d, 0x79, unchecked(0xe5), unchecked(0x89), unchecked(0x8c), unchecked(0xe3), 0x20, 0x30, unchecked(0xdc), unchecked(0xb7), 0x6c, 0x4a, unchecked(0xb5), 0x3f, unchecked(0x97), unchecked(0xd4), 0x62, 0x2d, 0x06, unchecked(0xa4), unchecked(0xa5), unchecked(0x83), 0x5f, 0x2a, unchecked(0xda), unchecked(0xc9), 0x00, 0x7e, unchecked(0xa2), 0x55, unchecked(0xbf), 0x11, unchecked(0xd5), unchecked(0x9c), unchecked(0xcf), 0x0e, 0x0a, 0x3d, 0x51, 0x7d, unchecked(0x93), 0x1b, unchecked(0xfe), unchecked(0xc4), 0x47, 0x09, unchecked(0x86), 0x0b, unchecked(0x8f), unchecked(0x9d), 0x6a, 0x07, unchecked(0xb9), unchecked(0xb0), unchecked(0x98), 0x18, 0x32, 0x71, 0x4b, unchecked(0xef), 0x3b, 0x70, unchecked(0xa0), unchecked(0xe4), 0x40, unchecked(0xff), unchecked(0xc3), unchecked(0xa9), unchecked(0xe6), 0x78, unchecked(0xf9), unchecked(0x8b), 0x46, unchecked(0x80), 0x1e, 0x38, unchecked(0xe1), unchecked(0xb8), unchecked(0xa8), unchecked(0xe0), 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05, unchecked(0xf1), 0x6e, unchecked(0x94), 0x28, unchecked(0x9a), unchecked(0x84), unchecked(0xe8), unchecked(0xa3), 0x4f, 0x77, unchecked(0xd3), unchecked(0x85), unchecked(0xe2), 0x52, unchecked(0xf2), unchecked(0x82), 0x50, 0x7a, 0x2f, 0x74, 0x53, unchecked(0xb3), 0x61, unchecked(0xaf), 0x39, 0x35, unchecked(0xde), unchecked(0xcd), 0x1f, unchecked(0x99), unchecked(0xac), unchecked(0xad), 0x72, 0x2c, unchecked(0xdd), unchecked(0xd0), unchecked(0x87), unchecked(0xbe), 0x5e, unchecked(0xa6), unchecked(0xec), 0x04, unchecked(0xc6), 0x03, 0x34, unchecked(0xfb), unchecked(0xdb), 0x59, unchecked(0xb6), unchecked(0xc2), 0x01, unchecked(0xf0), 0x5a, unchecked(0xed), unchecked(0xa7), 0x66, 0x21, 0x7f, unchecked(0x8a), 0x27, unchecked(0xc7), unchecked(0xc0), 0x29, unchecked(0xd7)};

		private static readonly byte[] S2 = new byte[]{unchecked(0x93), unchecked(0xd9), unchecked(0x9a), unchecked(0xb5), unchecked(0x98), 0x22, 0x45, unchecked(0xfc), unchecked(0xba), 0x6a, unchecked(0xdf), 0x02, unchecked(0x9f), unchecked(0xdc), 0x51, 0x59, 0x4a, 0x17, 0x2b, unchecked(0xc2), unchecked(0x94), unchecked(0xf4), unchecked(0xbb), unchecked(0xa3), 0x62, unchecked(0xe4), 0x71, unchecked(0xd4), unchecked(0xcd), 0x70, 0x16, unchecked(0xe1), 0x49, 0x3c, unchecked(0xc0), unchecked(0xd8), 0x5c, unchecked(0x9b), unchecked(0xad), unchecked(0x85), 0x53, unchecked(0xa1), 0x7a, unchecked(0xc8), 0x2d, unchecked(0xe0), unchecked(0xd1), 0x72, unchecked(0xa6), 0x2c, unchecked(0xc4), unchecked(0xe3), 0x76, 0x78, unchecked(0xb7), unchecked(0xb4), 0x09, 0x3b, 0x0e, 0x41, 0x4c, unchecked(0xde), unchecked(0xb2), unchecked(0x90), 0x25, unchecked(0xa5), unchecked(0xd7), 0x03, 0x11, 0x00, unchecked(0xc3), 0x2e, unchecked(0x92), unchecked(0xef), 0x4e, 0x12, unchecked(0x9d), 0x7d, unchecked(0xcb), 0x35, 0x10, unchecked(0xd5), 0x4f, unchecked(0x9e), 0x4d, unchecked(0xa9), 0x55, unchecked(0xc6), unchecked(0xd0), 0x7b, 0x18, unchecked(0x97), unchecked(0xd3), 0x36, unchecked(0xe6), 0x48, 0x56, unchecked(0x81), unchecked(0x8f), 0x77, unchecked(0xcc), unchecked(0x9c), unchecked(0xb9), unchecked(0xe2), unchecked(0xac), unchecked(0xb8), 0x2f, 0x15, unchecked(0xa4), 0x7c, unchecked(0xda), 0x38, 0x1e, 0x0b, 0x05, unchecked(0xd6), 0x14, 0x6e, 0x6c, 0x7e, 0x66, unchecked(0xfd), unchecked(0xb1), unchecked(0xe5), 0x60, unchecked(0xaf), 0x5e, 0x33, unchecked(0x87), unchecked(0xc9), unchecked(0xf0), 0x5d, 0x6d, 0x3f, unchecked(0x88), unchecked(0x8d), unchecked(0xc7), unchecked(0xf7), 0x1d, unchecked(0xe9), unchecked(0xec), unchecked(0xed), unchecked(0x80), 0x29, 0x27, unchecked(0xcf), unchecked(0x99), unchecked(0xa8), 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, unchecked(0x95), unchecked(0xd2), 0x3e, 0x5b, 0x40, unchecked(0x83), unchecked(0xb3), 0x69, 0x57, 0x1f, 0x07, 0x1c, unchecked(0x8a), unchecked(0xbc), 0x20, unchecked(0xeb), unchecked(0xce), unchecked(0x8e), unchecked(0xab), unchecked(0xee), 0x31, unchecked(0xa2), 0x73, unchecked(0xf9), unchecked(0xca), 0x3a, 0x1a, unchecked(0xfb), 0x0d, unchecked(0xc1), unchecked(0xfe), unchecked(0xfa), unchecked(0xf2), 0x6f, unchecked(0xbd), unchecked(0x96), unchecked(0xdd), 0x43, 0x52, unchecked(0xb6), 0x08, unchecked(0xf3), unchecked(0xae), unchecked(0xbe), 0x19, unchecked(0x89), 0x32, 0x26, unchecked(0xb0), unchecked(0xea), 0x4b, 0x64, unchecked(0x84), unchecked(0x82), 0x6b, unchecked(0xf5), 0x79, unchecked(0xbf), 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, unchecked(0xe8), unchecked(0x91), unchecked(0xf6), unchecked(0xff), 0x13, 0x58, unchecked(0xf1), 0x47, 0x0a, 0x7f, unchecked(0xc5), unchecked(0xa7), unchecked(0xe7), 0x61, 0x5a, 0x06, 0x46, 0x44, 0x42, 0x04, unchecked(0xa0), unchecked(0xdb), 0x39, unchecked(0x86), 0x54, unchecked(0xaa), unchecked(0x8c), 0x34, 0x21, unchecked(0x8b), unchecked(0xf8), 0x0c, 0x74, 0x67};

		private static readonly byte[] S3 = new byte[]{0x68, unchecked(0x8d), unchecked(0xca), 0x4d, 0x73, 0x4b, 0x4e, 0x2a, unchecked(0xd4), 0x52, 0x26, unchecked(0xb3), 0x54, 0x1e, 0x19, 0x1f, 0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, unchecked(0x83), 0x13, unchecked(0x8a), unchecked(0xb7), unchecked(0xd5), 0x25, 0x79, unchecked(0xf5), unchecked(0xbd), 0x58, 0x2f, 0x0d, 0x02, unchecked(0xed), 0x51, unchecked(0x9e), 0x11, unchecked(0xf2), 0x3e, 0x55, 0x5e, unchecked(0xd1), 0x16, 0x3c, 0x66, 0x70, 0x5d, unchecked(0xf3), 0x45, 0x40, unchecked(0xcc), unchecked(0xe8), unchecked(0x94), 0x56, 0x08, unchecked(0xce), 0x1a, 0x3a, unchecked(0xd2), unchecked(0xe1), unchecked(0xdf), unchecked(0xb5), 0x38, 0x6e, 0x0e, unchecked(0xe5), unchecked(0xf4), unchecked(0xf9), unchecked(0x86), unchecked(0xe9), 0x4f, unchecked(0xd6), unchecked(0x85), 0x23, unchecked(0xcf), 0x32, unchecked(0x99), 0x31, 0x14, unchecked(0xae), unchecked(0xee), unchecked(0xc8), 0x48, unchecked(0xd3), 0x30, unchecked(0xa1), unchecked(0x92), 0x41, unchecked(0xb1), 0x18, unchecked(0xc4), 0x2c, 0x71, 0x72, 0x44, 0x15, unchecked(0xfd), 0x37, unchecked(0xbe), 0x5f, unchecked(0xaa), unchecked(0x9b), unchecked(0x88), unchecked(0xd8), unchecked(0xab), unchecked(0x89), unchecked(0x9c), unchecked(0xfa), 0x60, unchecked(0xea), unchecked(0xbc), 0x62, 0x0c, 0x24, unchecked(0xa6), unchecked(0xa8), unchecked(0xec), 0x67, 0x20, unchecked(0xdb), 0x7c, 0x28, unchecked(0xdd), unchecked(0xac), 0x5b, 0x34, 0x7e, 0x10, unchecked(0xf1), 0x7b, unchecked(0x8f), 0x63, unchecked(0xa0), 0x05, unchecked(0x9a), 0x43, 0x77, 0x21, unchecked(0xbf), 0x27, 0x09, unchecked(0xc3), unchecked(0x9f), unchecked(0xb6), unchecked(0xd7), 0x29, unchecked(0xc2), unchecked(0xeb), unchecked(0xc0), unchecked(0xa4), unchecked(0x8b), unchecked(0x8c), 0x1d, unchecked(0xfb), unchecked(0xff), unchecked(0xc1), unchecked(0xb2), unchecked(0x97), 0x2e, unchecked(0xf8), 0x65, unchecked(0xf6), 0x75, 0x07, 0x04, 0x49, 0x33, unchecked(0xe4), unchecked(0xd9), unchecked(0xb9), unchecked(0xd0), 0x42, unchecked(0xc7), 0x6c, unchecked(0x90), 0x00, unchecked(0x8e), 0x6f, 0x50, 0x01, unchecked(0xc5), unchecked(0xda), 0x47, 0x3f, unchecked(0xcd), 0x69, unchecked(0xa2), unchecked(0xe2), 0x7a, unchecked(0xa7), unchecked(0xc6), unchecked(0x93), 0x0f, 0x0a, 0x06, unchecked(0xe6), 0x2b, unchecked(0x96), unchecked(0xa3), 0x1c, unchecked(0xaf), 0x6a, 0x12, unchecked(0x84), 0x39, unchecked(0xe7), unchecked(0xb0), unchecked(0x82), unchecked(0xf7), unchecked(0xfe), unchecked(0x9d), unchecked(0x87), 0x5c, unchecked(0x81), 0x35, unchecked(0xde), unchecked(0xb4), unchecked(0xa5), unchecked(0xfc), unchecked(0x80), unchecked(0xef), unchecked(0xcb), unchecked(0xbb), 0x6b, 0x76, unchecked(0xba), 0x5a, 0x7d, 0x78, 0x0b, unchecked(0x95), unchecked(0xe3), unchecked(0xad), 0x74, unchecked(0x98), 0x3b, 0x36, 0x64, 0x6d, unchecked(0xdc), unchecked(0xf0), 0x59, unchecked(0xa9), 0x4c, 0x17, 0x7f, unchecked(0x91), unchecked(0xb8), unchecked(0xc9), 0x57, 0x1b, unchecked(0xe0), 0x61};

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