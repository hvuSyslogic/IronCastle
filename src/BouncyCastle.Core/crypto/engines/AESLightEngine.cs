using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Pack = org.bouncycastle.util.Pack;

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
		private static readonly byte[] S = new byte[] {(byte)99, (byte)124, (byte)119, (byte)123, unchecked((byte)242), (byte)107, (byte)111, unchecked((byte)197), (byte)48, (byte)1, (byte)103, (byte)43, unchecked((byte)254), unchecked((byte)215), unchecked((byte)171), (byte)118, unchecked((byte)202), unchecked((byte)130), unchecked((byte)201), (byte)125, unchecked((byte)250), (byte)89, (byte)71, unchecked((byte)240), unchecked((byte)173), unchecked((byte)212), unchecked((byte)162), unchecked((byte)175), unchecked((byte)156), unchecked((byte)164), (byte)114, unchecked((byte)192), unchecked((byte)183), unchecked((byte)253), unchecked((byte)147), (byte)38, (byte)54, (byte)63, unchecked((byte)247), unchecked((byte)204), (byte)52, unchecked((byte)165), unchecked((byte)229), unchecked((byte)241), (byte)113, unchecked((byte)216), (byte)49, (byte)21, (byte)4, unchecked((byte)199), (byte)35, unchecked((byte)195), (byte)24, unchecked((byte)150), (byte)5, unchecked((byte)154), (byte)7, (byte)18, unchecked((byte)128), unchecked((byte)226), unchecked((byte)235), (byte)39, unchecked((byte)178), (byte)117, (byte)9, unchecked((byte)131), (byte)44, (byte)26, (byte)27, (byte)110, (byte)90, unchecked((byte)160), (byte)82, (byte)59, unchecked((byte)214), unchecked((byte)179), (byte)41, unchecked((byte)227), (byte)47, unchecked((byte)132), (byte)83, unchecked((byte)209), (byte)0, unchecked((byte)237), (byte)32, unchecked((byte)252), unchecked((byte)177), (byte)91, (byte)106, unchecked((byte)203), unchecked((byte)190), (byte)57, (byte)74, (byte)76, (byte)88, unchecked((byte)207), unchecked((byte)208), unchecked((byte)239), unchecked((byte)170), unchecked((byte)251), (byte)67, (byte)77, (byte)51, unchecked((byte)133), (byte)69, unchecked((byte)249), (byte)2, (byte)127, (byte)80, (byte)60, unchecked((byte)159), unchecked((byte)168), (byte)81, unchecked((byte)163), (byte)64, unchecked((byte)143), unchecked((byte)146), unchecked((byte)157), (byte)56, unchecked((byte)245), unchecked((byte)188), unchecked((byte)182), unchecked((byte)218), (byte)33, (byte)16, unchecked((byte)255), unchecked((byte)243), unchecked((byte)210), unchecked((byte)205), (byte)12, (byte)19, unchecked((byte)236), (byte)95, unchecked((byte)151), (byte)68, (byte)23, unchecked((byte)196), unchecked((byte)167), (byte)126, (byte)61, (byte)100, (byte)93, (byte)25, (byte)115, (byte)96, unchecked((byte)129), (byte)79, unchecked((byte)220), (byte)34, (byte)42, unchecked((byte)144), unchecked((byte)136), (byte)70, unchecked((byte)238), unchecked((byte)184), (byte)20, unchecked((byte)222), (byte)94, (byte)11, unchecked((byte)219), unchecked((byte)224), (byte)50, (byte)58, (byte)10, (byte)73, (byte)6, (byte)36, (byte)92, unchecked((byte)194), unchecked((byte)211), unchecked((byte)172), (byte)98, unchecked((byte)145), unchecked((byte)149), unchecked((byte)228), (byte)121, unchecked((byte)231), unchecked((byte)200), (byte)55, (byte)109, unchecked((byte)141), unchecked((byte)213), (byte)78, unchecked((byte)169), (byte)108, (byte)86, unchecked((byte)244), unchecked((byte)234), (byte)101, (byte)122, unchecked((byte)174), (byte)8, unchecked((byte)186), (byte)120, (byte)37, (byte)46, (byte)28, unchecked((byte)166), unchecked((byte)180), unchecked((byte)198), unchecked((byte)232), unchecked((byte)221), (byte)116, (byte)31, (byte)75, unchecked((byte)189), unchecked((byte)139), unchecked((byte)138), (byte)112, (byte)62, unchecked((byte)181), (byte)102, (byte)72, (byte)3, unchecked((byte)246), (byte)14, (byte)97, (byte)53, (byte)87, unchecked((byte)185), unchecked((byte)134), unchecked((byte)193), (byte)29, unchecked((byte)158), unchecked((byte)225), unchecked((byte)248), unchecked((byte)152), (byte)17, (byte)105, unchecked((byte)217), unchecked((byte)142), unchecked((byte)148), unchecked((byte)155), (byte)30, unchecked((byte)135), unchecked((byte)233), unchecked((byte)206), (byte)85, (byte)40, unchecked((byte)223), unchecked((byte)140), unchecked((byte)161), unchecked((byte)137), (byte)13, unchecked((byte)191), unchecked((byte)230), (byte)66, (byte)104, (byte)65, unchecked((byte)153), (byte)45, (byte)15, unchecked((byte)176), (byte)84, unchecked((byte)187), (byte)22};

		// The inverse S-box
		private static readonly byte[] Si = new byte[] {(byte)82, (byte)9, (byte)106, unchecked((byte)213), (byte)48, (byte)54, unchecked((byte)165), (byte)56, unchecked((byte)191), (byte)64, unchecked((byte)163), unchecked((byte)158), unchecked((byte)129), unchecked((byte)243), unchecked((byte)215), unchecked((byte)251), (byte)124, unchecked((byte)227), (byte)57, unchecked((byte)130), unchecked((byte)155), (byte)47, unchecked((byte)255), unchecked((byte)135), (byte)52, unchecked((byte)142), (byte)67, (byte)68, unchecked((byte)196), unchecked((byte)222), unchecked((byte)233), unchecked((byte)203), (byte)84, (byte)123, unchecked((byte)148), (byte)50, unchecked((byte)166), unchecked((byte)194), (byte)35, (byte)61, unchecked((byte)238), (byte)76, unchecked((byte)149), (byte)11, (byte)66, unchecked((byte)250), unchecked((byte)195), (byte)78, (byte)8, (byte)46, unchecked((byte)161), (byte)102, (byte)40, unchecked((byte)217), (byte)36, unchecked((byte)178), (byte)118, (byte)91, unchecked((byte)162), (byte)73, (byte)109, unchecked((byte)139), unchecked((byte)209), (byte)37, (byte)114, unchecked((byte)248), unchecked((byte)246), (byte)100, unchecked((byte)134), (byte)104, unchecked((byte)152), (byte)22, unchecked((byte)212), unchecked((byte)164), (byte)92, unchecked((byte)204), (byte)93, (byte)101, unchecked((byte)182), unchecked((byte)146), (byte)108, (byte)112, (byte)72, (byte)80, unchecked((byte)253), unchecked((byte)237), unchecked((byte)185), unchecked((byte)218), (byte)94, (byte)21, (byte)70, (byte)87, unchecked((byte)167), unchecked((byte)141), unchecked((byte)157), unchecked((byte)132), unchecked((byte)144), unchecked((byte)216), unchecked((byte)171), (byte)0, unchecked((byte)140), unchecked((byte)188), unchecked((byte)211), (byte)10, unchecked((byte)247), unchecked((byte)228), (byte)88, (byte)5, unchecked((byte)184), unchecked((byte)179), (byte)69, (byte)6, unchecked((byte)208), (byte)44, (byte)30, unchecked((byte)143), unchecked((byte)202), (byte)63, (byte)15, (byte)2, unchecked((byte)193), unchecked((byte)175), unchecked((byte)189), (byte)3, (byte)1, (byte)19, unchecked((byte)138), (byte)107, (byte)58, unchecked((byte)145), (byte)17, (byte)65, (byte)79, (byte)103, unchecked((byte)220), unchecked((byte)234), unchecked((byte)151), unchecked((byte)242), unchecked((byte)207), unchecked((byte)206), unchecked((byte)240), unchecked((byte)180), unchecked((byte)230), (byte)115, unchecked((byte)150), unchecked((byte)172), (byte)116, (byte)34, unchecked((byte)231), unchecked((byte)173), (byte)53, unchecked((byte)133), unchecked((byte)226), unchecked((byte)249), (byte)55, unchecked((byte)232), (byte)28, (byte)117, unchecked((byte)223), (byte)110, (byte)71, unchecked((byte)241), (byte)26, (byte)113, (byte)29, (byte)41, unchecked((byte)197), unchecked((byte)137), (byte)111, unchecked((byte)183), (byte)98, (byte)14, unchecked((byte)170), (byte)24, unchecked((byte)190), (byte)27, unchecked((byte)252), (byte)86, (byte)62, (byte)75, unchecked((byte)198), unchecked((byte)210), (byte)121, (byte)32, unchecked((byte)154), unchecked((byte)219), unchecked((byte)192), unchecked((byte)254), (byte)120, unchecked((byte)205), (byte)90, unchecked((byte)244), (byte)31, unchecked((byte)221), unchecked((byte)168), (byte)51, unchecked((byte)136), (byte)7, unchecked((byte)199), (byte)49, unchecked((byte)177), (byte)18, (byte)16, (byte)89, (byte)39, unchecked((byte)128), unchecked((byte)236), (byte)95, (byte)96, (byte)81, (byte)127, unchecked((byte)169), (byte)25, unchecked((byte)181), (byte)74, (byte)13, (byte)45, unchecked((byte)229), (byte)122, unchecked((byte)159), unchecked((byte)147), unchecked((byte)201), unchecked((byte)156), unchecked((byte)239), unchecked((byte)160), unchecked((byte)224), (byte)59, (byte)77, unchecked((byte)174), (byte)42, unchecked((byte)245), unchecked((byte)176), unchecked((byte)200), unchecked((byte)235), unchecked((byte)187), (byte)60, unchecked((byte)131), (byte)83, unchecked((byte)153), (byte)97, (byte)23, (byte)43, (byte)4, (byte)126, unchecked((byte)186), (byte)119, unchecked((byte)214), (byte)38, unchecked((byte)225), (byte)105, (byte)20, (byte)99, (byte)85, (byte)33, (byte)12, (byte)125};

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