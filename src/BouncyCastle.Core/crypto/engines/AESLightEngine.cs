using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
		
	/// <summary>
	/// an implementation of the AES (Rijndael), from FIPS-197.
	/// <para>
	/// For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
	/// 
	/// This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
	/// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
	/// 
	/// There are three levels of tradeoff of speed vs memory
	/// Because java has no preprocessor, they are written as three separate classes from which to choose
	/// 
	/// The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
	/// and 4 for decryption.
	/// 
	/// The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
	/// adding 12 rotate operations per round to compute the values contained in the other tables from
	/// the contents of the first
	/// 
	/// The slowest version uses no static tables at all and computes the values
	/// in each round.
	/// </para>
	/// <para>
	/// This file contains the slowest performance version with no static tables
	/// for round precomputation, but it has the smallest foot print.
	/// 
	/// </para>
	/// </summary>
	public class AESLightEngine : BlockCipher
	{
		// The S box
		private static readonly byte[] S = new byte[] {99, 124, 119, 123, unchecked(242), 107, 111, unchecked(197), 48, 1, 103, 43, unchecked(254), unchecked(215), unchecked(171), 118, unchecked(202), unchecked(130), unchecked(201), 125, unchecked(250), 89, 71, unchecked(240), unchecked(173), unchecked(212), unchecked(162), unchecked(175), unchecked(156), unchecked(164), 114, unchecked(192), unchecked(183), unchecked(253), unchecked(147), 38, 54, 63, unchecked(247), unchecked(204), 52, unchecked(165), unchecked(229), unchecked(241), 113, unchecked(216), 49, 21, 4, unchecked(199), 35, unchecked(195), 24, unchecked(150), 5, unchecked(154), 7, 18, unchecked(128), unchecked(226), unchecked(235), 39, unchecked(178), 117, 9, unchecked(131), 44, 26, 27, 110, 90, unchecked(160), 82, 59, unchecked(214), unchecked(179), 41, unchecked(227), 47, unchecked(132), 83, unchecked(209), 0, unchecked(237), 32, unchecked(252), unchecked(177), 91, 106, unchecked(203), unchecked(190), 57, 74, 76, 88, unchecked(207), unchecked(208), unchecked(239), unchecked(170), unchecked(251), 67, 77, 51, unchecked(133), 69, unchecked(249), 2, 127, 80, 60, unchecked(159), unchecked(168), 81, unchecked(163), 64, unchecked(143), unchecked(146), unchecked(157), 56, unchecked(245), unchecked(188), unchecked(182), unchecked(218), 33, 16, unchecked(255), unchecked(243), unchecked(210), unchecked(205), 12, 19, unchecked(236), 95, unchecked(151), 68, 23, unchecked(196), unchecked(167), 126, 61, 100, 93, 25, 115, 96, unchecked(129), 79, unchecked(220), 34, 42, unchecked(144), unchecked(136), 70, unchecked(238), unchecked(184), 20, unchecked(222), 94, 11, unchecked(219), unchecked(224), 50, 58, 10, 73, 6, 36, 92, unchecked(194), unchecked(211), unchecked(172), 98, unchecked(145), unchecked(149), unchecked(228), 121, unchecked(231), unchecked(200), 55, 109, unchecked(141), unchecked(213), 78, unchecked(169), 108, 86, unchecked(244), unchecked(234), 101, 122, unchecked(174), 8, unchecked(186), 120, 37, 46, 28, unchecked(166), unchecked(180), unchecked(198), unchecked(232), unchecked(221), 116, 31, 75, unchecked(189), unchecked(139), unchecked(138), 112, 62, unchecked(181), 102, 72, 3, unchecked(246), 14, 97, 53, 87, unchecked(185), unchecked(134), unchecked(193), 29, unchecked(158), unchecked(225), unchecked(248), unchecked(152), 17, 105, unchecked(217), unchecked(142), unchecked(148), unchecked(155), 30, unchecked(135), unchecked(233), unchecked(206), 85, 40, unchecked(223), unchecked(140), unchecked(161), unchecked(137), 13, unchecked(191), unchecked(230), 66, 104, 65, unchecked(153), 45, 15, unchecked(176), 84, unchecked(187), 22};

		// The inverse S-box
		private static readonly byte[] Si = new byte[] {82, 9, 106, unchecked(213), 48, 54, unchecked(165), 56, unchecked(191), 64, unchecked(163), unchecked(158), unchecked(129), unchecked(243), unchecked(215), unchecked(251), 124, unchecked(227), 57, unchecked(130), unchecked(155), 47, unchecked(255), unchecked(135), 52, unchecked(142), 67, 68, unchecked(196), unchecked(222), unchecked(233), unchecked(203), 84, 123, unchecked(148), 50, unchecked(166), unchecked(194), 35, 61, unchecked(238), 76, unchecked(149), 11, 66, unchecked(250), unchecked(195), 78, 8, 46, unchecked(161), 102, 40, unchecked(217), 36, unchecked(178), 118, 91, unchecked(162), 73, 109, unchecked(139), unchecked(209), 37, 114, unchecked(248), unchecked(246), 100, unchecked(134), 104, unchecked(152), 22, unchecked(212), unchecked(164), 92, unchecked(204), 93, 101, unchecked(182), unchecked(146), 108, 112, 72, 80, unchecked(253), unchecked(237), unchecked(185), unchecked(218), 94, 21, 70, 87, unchecked(167), unchecked(141), unchecked(157), unchecked(132), unchecked(144), unchecked(216), unchecked(171), 0, unchecked(140), unchecked(188), unchecked(211), 10, unchecked(247), unchecked(228), 88, 5, unchecked(184), unchecked(179), 69, 6, unchecked(208), 44, 30, unchecked(143), unchecked(202), 63, 15, 2, unchecked(193), unchecked(175), unchecked(189), 3, 1, 19, unchecked(138), 107, 58, unchecked(145), 17, 65, 79, 103, unchecked(220), unchecked(234), unchecked(151), unchecked(242), unchecked(207), unchecked(206), unchecked(240), unchecked(180), unchecked(230), 115, unchecked(150), unchecked(172), 116, 34, unchecked(231), unchecked(173), 53, unchecked(133), unchecked(226), unchecked(249), 55, unchecked(232), 28, 117, unchecked(223), 110, 71, unchecked(241), 26, 113, 29, 41, unchecked(197), unchecked(137), 111, unchecked(183), 98, 14, unchecked(170), 24, unchecked(190), 27, unchecked(252), 86, 62, 75, unchecked(198), unchecked(210), 121, 32, unchecked(154), unchecked(219), unchecked(192), unchecked(254), 120, unchecked(205), 90, unchecked(244), 31, unchecked(221), unchecked(168), 51, unchecked(136), 7, unchecked(199), 49, unchecked(177), 18, 16, 89, 39, unchecked(128), unchecked(236), 95, 96, 81, 127, unchecked(169), 25, unchecked(181), 74, 13, 45, unchecked(229), 122, unchecked(159), unchecked(147), unchecked(201), unchecked(156), unchecked(239), unchecked(160), unchecked(224), 59, 77, unchecked(174), 42, unchecked(245), unchecked(176), unchecked(200), unchecked(235), unchecked(187), 60, unchecked(131), 83, unchecked(153), 97, 23, 43, 4, 126, unchecked(186), 119, unchecked(214), 38, unchecked(225), 105, 20, 99, 85, 33, 12, 125};

		// vector used in calculating key schedule (powers of x in GF(256))
		private static readonly int[] rcon = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

		private static int shift(int r, int shift)
		{
			return ((int)((uint)r >> shift)) | (r << -shift);
		}

		/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

		private const int m1 = unchecked((int)0x80808080);
		private const int m2 = 0x7f7f7f7f;
		private const int m3 = 0x0000001b;
		private const int m4 = unchecked((int)0xC0C0C0C0);
		private const int m5 = 0x3f3f3f3f;

		private static int FFmulX(int x)
		{
			return (((x & m2) << 1) ^ (((int)((uint)(x & m1) >> 7)) * m3));
		}

		private static int FFmulX2(int x)
		{
			int t0 = (x & m5) << 2;
			int t1 = (x & m4);
				t1 ^= ((int)((uint)t1 >> 1));
			return t0 ^ ((int)((uint)t1 >> 2)) ^ ((int)((uint)t1 >> 5));
		}

		/* 
		   The following defines provide alternative definitions of FFmulX that might
		   give improved performance if a fast 32-bit multiply is not available.
		   
		   private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
		   private static final int  m4 = 0x1b1b1b1b;
		   private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 
	
		*/

		private static int mcol(int x)
		{
			int t0, t1;
			t0 = shift(x, 8);
			t1 = x ^ t0;
			return shift(t1, 16) ^ t0 ^ FFmulX(t1);
		}

		private static int inv_mcol(int x)
		{
			int t0, t1;
			t0 = x;
			t1 = t0 ^ shift(t0, 8);
			t0 ^= FFmulX(t1);
			t1 ^= FFmulX2(t0);
			t0 ^= t1 ^ shift(t1, 16);
			return t0;
		}


		private static int subWord(int x)
		{
			return (S[x & 255] & 255 | ((S[(x >> 8) & 255] & 255) << 8) | ((S[(x>>16) & 255] & 255) << 16) | S[(x>>24) & 255] << 24);
		}

		/// <summary>
		/// Calculate the necessary round keys
		/// The number of calculations depends on key size and block size
		/// AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
		/// This code is written assuming those are the only possible values
		/// </summary>
		private int[][] generateWorkingKey(byte[] key, bool forEncryption)
		{
			int keyLen = key.Length;
			if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
			{
				throw new IllegalArgumentException("Key length not 128/192/256 bits.");
			}

			int KC = keyLen >> 2;
			ROUNDS = KC + 6; // This is not always true for the generalized Rijndael that allows larger block sizes
			int[][] W = RectangularArrays.ReturnRectangularIntArray(ROUNDS + 1, 4); // 4 words in a block

			switch (KC)
			{
			case 4:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;

				for (int i = 1; i <= 10; ++i)
				{
					int u = subWord(shift(t3, 8)) ^ rcon[i - 1];
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
				}

				break;
			}
			case 6:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;
				int t4 = Pack.littleEndianToInt(key, 16);
				W[1][0] = t4;
				int t5 = Pack.littleEndianToInt(key, 20);
				W[1][1] = t5;

				int rcon = 1;
				int u = subWord(shift(t5, 8)) ^ rcon;
				rcon <<= 1;
				t0 ^= u;
				W[1][2] = t0;
				t1 ^= t0;
				W[1][3] = t1;
				t2 ^= t1;
				W[2][0] = t2;
				t3 ^= t2;
				W[2][1] = t3;
				t4 ^= t3;
				W[2][2] = t4;
				t5 ^= t4;
				W[2][3] = t5;

				for (int i = 3; i < 12; i += 3)
				{
					u = subWord(shift(t5, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
					t4 ^= t3;
					W[i + 1][0] = t4;
					t5 ^= t4;
					W[i + 1][1] = t5;
					u = subWord(shift(t5, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i + 1][2] = t0;
					t1 ^= t0;
					W[i + 1][3] = t1;
					t2 ^= t1;
					W[i + 2][0] = t2;
					t3 ^= t2;
					W[i + 2][1] = t3;
					t4 ^= t3;
					W[i + 2][2] = t4;
					t5 ^= t4;
					W[i + 2][3] = t5;
				}

				u = subWord(shift(t5, 8)) ^ rcon;
				t0 ^= u;
				W[12][0] = t0;
				t1 ^= t0;
				W[12][1] = t1;
				t2 ^= t1;
				W[12][2] = t2;
				t3 ^= t2;
				W[12][3] = t3;

				break;
			}
			case 8:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;
				int t4 = Pack.littleEndianToInt(key, 16);
				W[1][0] = t4;
				int t5 = Pack.littleEndianToInt(key, 20);
				W[1][1] = t5;
				int t6 = Pack.littleEndianToInt(key, 24);
				W[1][2] = t6;
				int t7 = Pack.littleEndianToInt(key, 28);
				W[1][3] = t7;

				int u, rcon = 1;

				for (int i = 2; i < 14; i += 2)
				{
					u = subWord(shift(t7, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
					u = subWord(t3);
					t4 ^= u;
					W[i + 1][0] = t4;
					t5 ^= t4;
					W[i + 1][1] = t5;
					t6 ^= t5;
					W[i + 1][2] = t6;
					t7 ^= t6;
					W[i + 1][3] = t7;
				}

				u = subWord(shift(t7, 8)) ^ rcon;
				t0 ^= u;
				W[14][0] = t0;
				t1 ^= t0;
				W[14][1] = t1;
				t2 ^= t1;
				W[14][2] = t2;
				t3 ^= t2;
				W[14][3] = t3;

				break;
			}
			default:
			{
				throw new IllegalStateException("Should never get here");
			}
			}

			if (!forEncryption)
			{
				for (int j = 1; j < ROUNDS; j++)
				{
					for (int i = 0; i < 4; i++)
					{
						W[j][i] = inv_mcol(W[j][i]);
					}
				}
			}

			return W;
		}

		private int ROUNDS;
		private int[][] WorkingKey = null;
		private int C0, C1, C2, C3;
		private bool forEncryption;

		private const int BLOCK_SIZE = 16;

		/// <summary>
		/// default constructor - 128 bit block size.
		/// </summary>
		public AESLightEngine()
		{
		}

		/// <summary>
		/// initialise an AES cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				WorkingKey = generateWorkingKey(((KeyParameter)@params).getKey(), forEncryption);
				this.forEncryption = forEncryption;
				return;
			}

			throw new IllegalArgumentException("invalid parameter passed to AES init - " + @params.GetType().getName());
		}

		public virtual string getAlgorithmName()
		{
			return "AES";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (WorkingKey == null)
			{
				throw new IllegalStateException("AES engine not initialised");
			}

			if ((inOff + (32 / 2)) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + (32 / 2)) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (forEncryption)
			{
				unpackBlock(@in, inOff);
				encryptBlock(WorkingKey);
				packBlock(@out, outOff);
			}
			else
			{
				unpackBlock(@in, inOff);
				decryptBlock(WorkingKey);
				packBlock(@out, outOff);
			}

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
		}

		private void unpackBlock(byte[] bytes, int off)
		{
			int index = off;

			C0 = (bytes[index++] & 0xff);
			C0 |= (bytes[index++] & 0xff) << 8;
			C0 |= (bytes[index++] & 0xff) << 16;
			C0 |= bytes[index++] << 24;

			C1 = (bytes[index++] & 0xff);
			C1 |= (bytes[index++] & 0xff) << 8;
			C1 |= (bytes[index++] & 0xff) << 16;
			C1 |= bytes[index++] << 24;

			C2 = (bytes[index++] & 0xff);
			C2 |= (bytes[index++] & 0xff) << 8;
			C2 |= (bytes[index++] & 0xff) << 16;
			C2 |= bytes[index++] << 24;

			C3 = (bytes[index++] & 0xff);
			C3 |= (bytes[index++] & 0xff) << 8;
			C3 |= (bytes[index++] & 0xff) << 16;
			C3 |= bytes[index++] << 24;
		}

		private void packBlock(byte[] bytes, int off)
		{
			int index = off;

			bytes[index++] = (byte)C0;
			bytes[index++] = (byte)(C0 >> 8);
			bytes[index++] = (byte)(C0 >> 16);
			bytes[index++] = (byte)(C0 >> 24);

			bytes[index++] = (byte)C1;
			bytes[index++] = (byte)(C1 >> 8);
			bytes[index++] = (byte)(C1 >> 16);
			bytes[index++] = (byte)(C1 >> 24);

			bytes[index++] = (byte)C2;
			bytes[index++] = (byte)(C2 >> 8);
			bytes[index++] = (byte)(C2 >> 16);
			bytes[index++] = (byte)(C2 >> 24);

			bytes[index++] = (byte)C3;
			bytes[index++] = (byte)(C3 >> 8);
			bytes[index++] = (byte)(C3 >> 16);
			bytes[index++] = (byte)(C3 >> 24);
		}

		private void encryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[0][0];
			int t1 = this.C1 ^ KW[0][1];
			int t2 = this.C2 ^ KW[0][2];

			int r = 1, r0, r1, r2, r3 = this.C3 ^ KW[0][3];
			while (r < ROUNDS - 1)
			{
				r0 = mcol((S[t0 & 255] & 255) ^ ((S[(t1 >> 8) & 255] & 255) << 8) ^ ((S[(t2>>16) & 255] & 255) << 16) ^ (S[(r3>>24) & 255] << 24)) ^ KW[r][0];
				r1 = mcol((S[t1 & 255] & 255) ^ ((S[(t2 >> 8) & 255] & 255) << 8) ^ ((S[(r3>>16) & 255] & 255) << 16) ^ (S[(t0>>24) & 255] << 24)) ^ KW[r][1];
				r2 = mcol((S[t2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(t0>>16) & 255] & 255) << 16) ^ (S[(t1>>24) & 255] << 24)) ^ KW[r][2];
				r3 = mcol((S[r3 & 255] & 255) ^ ((S[(t0 >> 8) & 255] & 255) << 8) ^ ((S[(t1>>16) & 255] & 255) << 16) ^ (S[(t2>>24) & 255] << 24)) ^ KW[r++][3];
				t0 = mcol((S[r0 & 255] & 255) ^ ((S[(r1 >> 8) & 255] & 255) << 8) ^ ((S[(r2>>16) & 255] & 255) << 16) ^ (S[(r3>>24) & 255] << 24)) ^ KW[r][0];
				t1 = mcol((S[r1 & 255] & 255) ^ ((S[(r2 >> 8) & 255] & 255) << 8) ^ ((S[(r3>>16) & 255] & 255) << 16) ^ (S[(r0>>24) & 255] << 24)) ^ KW[r][1];
				t2 = mcol((S[r2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(r0>>16) & 255] & 255) << 16) ^ (S[(r1>>24) & 255] << 24)) ^ KW[r][2];
				r3 = mcol((S[r3 & 255] & 255) ^ ((S[(r0 >> 8) & 255] & 255) << 8) ^ ((S[(r1>>16) & 255] & 255) << 16) ^ (S[(r2>>24) & 255] << 24)) ^ KW[r++][3];
			}

			r0 = mcol((S[t0 & 255] & 255) ^ ((S[(t1 >> 8) & 255] & 255) << 8) ^ ((S[(t2>>16) & 255] & 255) << 16) ^ (S[(r3>>24) & 255] << 24)) ^ KW[r][0];
			r1 = mcol((S[t1 & 255] & 255) ^ ((S[(t2 >> 8) & 255] & 255) << 8) ^ ((S[(r3>>16) & 255] & 255) << 16) ^ (S[(t0>>24) & 255] << 24)) ^ KW[r][1];
			r2 = mcol((S[t2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(t0>>16) & 255] & 255) << 16) ^ (S[(t1>>24) & 255] << 24)) ^ KW[r][2];
			r3 = mcol((S[r3 & 255] & 255) ^ ((S[(t0 >> 8) & 255] & 255) << 8) ^ ((S[(t1>>16) & 255] & 255) << 16) ^ (S[(t2>>24) & 255] << 24)) ^ KW[r++][3];

			// the final round is a simple function of S

			this.C0 = (S[r0 & 255] & 255) ^ ((S[(r1 >> 8) & 255] & 255) << 8) ^ ((S[(r2>>16) & 255] & 255) << 16) ^ (S[(r3>>24) & 255] << 24) ^ KW[r][0];
			this.C1 = (S[r1 & 255] & 255) ^ ((S[(r2 >> 8) & 255] & 255) << 8) ^ ((S[(r3>>16) & 255] & 255) << 16) ^ (S[(r0>>24) & 255] << 24) ^ KW[r][1];
			this.C2 = (S[r2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(r0>>16) & 255] & 255) << 16) ^ (S[(r1>>24) & 255] << 24) ^ KW[r][2];
			this.C3 = (S[r3 & 255] & 255) ^ ((S[(r0 >> 8) & 255] & 255) << 8) ^ ((S[(r1>>16) & 255] & 255) << 16) ^ (S[(r2>>24) & 255] << 24) ^ KW[r][3];
		}

		private void decryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[ROUNDS][0];
			int t1 = this.C1 ^ KW[ROUNDS][1];
			int t2 = this.C2 ^ KW[ROUNDS][2];

			int r = ROUNDS - 1, r0, r1, r2, r3 = this.C3 ^ KW[ROUNDS][3];
			while (r > 1)
			{
				r0 = inv_mcol((Si[t0 & 255] & 255) ^ ((Si[(r3 >> 8) & 255] & 255) << 8) ^ ((Si[(t2>>16) & 255] & 255) << 16) ^ (Si[(t1>>24) & 255] << 24)) ^ KW[r][0];
				r1 = inv_mcol((Si[t1 & 255] & 255) ^ ((Si[(t0 >> 8) & 255] & 255) << 8) ^ ((Si[(r3>>16) & 255] & 255) << 16) ^ (Si[(t2>>24) & 255] << 24)) ^ KW[r][1];
				r2 = inv_mcol((Si[t2 & 255] & 255) ^ ((Si[(t1 >> 8) & 255] & 255) << 8) ^ ((Si[(t0>>16) & 255] & 255) << 16) ^ (Si[(r3>>24) & 255] << 24)) ^ KW[r][2];
				r3 = inv_mcol((Si[r3 & 255] & 255) ^ ((Si[(t2 >> 8) & 255] & 255) << 8) ^ ((Si[(t1>>16) & 255] & 255) << 16) ^ (Si[(t0>>24) & 255] << 24)) ^ KW[r--][3];
				t0 = inv_mcol((Si[r0 & 255] & 255) ^ ((Si[(r3 >> 8) & 255] & 255) << 8) ^ ((Si[(r2>>16) & 255] & 255) << 16) ^ (Si[(r1>>24) & 255] << 24)) ^ KW[r][0];
				t1 = inv_mcol((Si[r1 & 255] & 255) ^ ((Si[(r0 >> 8) & 255] & 255) << 8) ^ ((Si[(r3>>16) & 255] & 255) << 16) ^ (Si[(r2>>24) & 255] << 24)) ^ KW[r][1];
				t2 = inv_mcol((Si[r2 & 255] & 255) ^ ((Si[(r1 >> 8) & 255] & 255) << 8) ^ ((Si[(r0>>16) & 255] & 255) << 16) ^ (Si[(r3>>24) & 255] << 24)) ^ KW[r][2];
				r3 = inv_mcol((Si[r3 & 255] & 255) ^ ((Si[(r2 >> 8) & 255] & 255) << 8) ^ ((Si[(r1>>16) & 255] & 255) << 16) ^ (Si[(r0>>24) & 255] << 24)) ^ KW[r--][3];
			}

			r0 = inv_mcol((Si[t0 & 255] & 255) ^ ((Si[(r3 >> 8) & 255] & 255) << 8) ^ ((Si[(t2>>16) & 255] & 255) << 16) ^ (Si[(t1>>24) & 255] << 24)) ^ KW[r][0];
			r1 = inv_mcol((Si[t1 & 255] & 255) ^ ((Si[(t0 >> 8) & 255] & 255) << 8) ^ ((Si[(r3>>16) & 255] & 255) << 16) ^ (Si[(t2>>24) & 255] << 24)) ^ KW[r][1];
			r2 = inv_mcol((Si[t2 & 255] & 255) ^ ((Si[(t1 >> 8) & 255] & 255) << 8) ^ ((Si[(t0>>16) & 255] & 255) << 16) ^ (Si[(r3>>24) & 255] << 24)) ^ KW[r][2];
			r3 = inv_mcol((Si[r3 & 255] & 255) ^ ((Si[(t2 >> 8) & 255] & 255) << 8) ^ ((Si[(t1>>16) & 255] & 255) << 16) ^ (Si[(t0>>24) & 255] << 24)) ^ KW[r][3];

			// the final round's table is a simple function of Si

			this.C0 = (Si[r0 & 255] & 255) ^ ((Si[(r3 >> 8) & 255] & 255) << 8) ^ ((Si[(r2>>16) & 255] & 255) << 16) ^ (Si[(r1>>24) & 255] << 24) ^ KW[0][0];
			this.C1 = (Si[r1 & 255] & 255) ^ ((Si[(r0 >> 8) & 255] & 255) << 8) ^ ((Si[(r3>>16) & 255] & 255) << 16) ^ (Si[(r2>>24) & 255] << 24) ^ KW[0][1];
			this.C2 = (Si[r2 & 255] & 255) ^ ((Si[(r1 >> 8) & 255] & 255) << 8) ^ ((Si[(r0>>16) & 255] & 255) << 16) ^ (Si[(r3>>24) & 255] << 24) ^ KW[0][2];
			this.C3 = (Si[r3 & 255] & 255) ^ ((Si[(r2 >> 8) & 255] & 255) << 8) ^ ((Si[(r1>>16) & 255] & 255) << 16) ^ (Si[(r0>>24) & 255] << 24) ^ KW[0][3];
		}
	}

}