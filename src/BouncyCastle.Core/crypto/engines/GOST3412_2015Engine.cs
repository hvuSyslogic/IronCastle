using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
		
	/// <summary>
	/// Implementation of GOST 3412 2015 (aka "Kuznyechik") RFC 7801, GOST 3412
	/// </summary>
	public class GOST3412_2015Engine : BlockCipher
	{
		private bool InstanceFieldsInitialized = false;

		public GOST3412_2015Engine()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			SUB_LENGTH = KEY_LENGTH / 2;
		}


		private static readonly byte[] PI = new byte[] {unchecked(unchecked((byte)-4)), unchecked((byte)-18), unchecked((byte)-35), 17, unchecked((byte)-49), 110, 49, 22, unchecked((byte)-5), unchecked((byte)-60), unchecked((byte)-6), unchecked((byte)-38), 35, unchecked((byte)-59), 4, 77, unchecked((byte)-23), 119, unchecked((byte)-16), unchecked((byte)-37), unchecked((byte)-109), 46, unchecked((byte)-103), unchecked((byte)-70), 23, 54, unchecked((byte)-15), unchecked((byte)-69), 20, unchecked((byte)-51), 95, unchecked((byte)-63), unchecked((byte)-7), 24, 101, 90, unchecked((byte)-30), 92, unchecked((byte)-17), 33, unchecked((byte)-127), 28, 60, 66, unchecked((byte)-117), 1, unchecked((byte)-114), 79, 5, unchecked((byte)-124), 2, unchecked((byte)-82), unchecked((byte)-29), 106, unchecked((byte)-113), unchecked((byte)-96), 6, 11, unchecked((byte)-19), unchecked((byte)-104), 127, unchecked((byte)-44), unchecked((byte)-45), 31, unchecked((byte)-21), 52, 44, 81, unchecked((byte)-22), unchecked((byte)-56), 72, unchecked((byte)-85), unchecked((byte)-14), 42, 104, unchecked((byte)-94), unchecked((byte)-3), 58, unchecked((byte)-50), unchecked((byte)-52), unchecked((byte)-75), 112, 14, 86, 8, 12, 118, 18, unchecked((byte)-65), 114, 19, 71, unchecked((byte)-100), unchecked((byte)-73), 93, unchecked((byte)-121), 21, unchecked((byte)-95), unchecked((byte)-106), 41, 16, 123, unchecked((byte)-102), unchecked((byte)-57), unchecked((byte)-13), unchecked((byte)-111), 120, 111, unchecked((byte)-99), unchecked((byte)-98), unchecked((byte)-78), unchecked((byte)-79), 50, 117, 25, 61, unchecked((byte)-1), 53, unchecked((byte)-118), 126, 109, 84, unchecked((byte)-58), unchecked((byte)-128), unchecked((byte)-61), unchecked((byte)-67), 13, 87, unchecked((byte)-33), unchecked((byte)-11), 36, unchecked((byte)-87), 62, unchecked((byte)-88), 67, unchecked((byte)-55), unchecked((byte)-41), 121, unchecked((byte)-42), unchecked((byte)-10), 124, 34, unchecked((byte)-71), 3, unchecked((byte)-32), 15, unchecked((byte)-20), unchecked((byte)-34), 122, unchecked((byte)-108), unchecked((byte)-80), unchecked((byte)-68), unchecked((byte)-36), unchecked((byte)-24), 40, 80, 78, 51, 10, 74, unchecked((byte)-89), unchecked((byte)-105), 96, 115, 30, 0, 98, 68, 26, unchecked((byte)-72), 56, unchecked((byte)-126), 100, unchecked((byte)-97), 38, 65, unchecked((byte)-83), 69, 70, unchecked((byte)-110), 39, 94, 85, 47, unchecked((byte)-116), unchecked((byte)-93), unchecked((byte)-91), 125, 105, unchecked((byte)-43), unchecked((byte)-107), 59, 7, 88, unchecked((byte)-77), 64, unchecked((byte)-122), unchecked((byte)-84), 29, unchecked((byte)-9), 48, 55, 107, unchecked((byte)-28), unchecked((byte)-120), unchecked((byte)-39), unchecked((byte)-25), unchecked((byte)-119), unchecked((byte)-31), 27, unchecked((byte)-125), 73, 76, 63, unchecked((byte)-8), unchecked((byte)-2), unchecked((byte)-115), 83, unchecked((byte)-86), unchecked((byte)-112), unchecked((byte)-54), unchecked((byte)-40), unchecked((byte)-123), 97, 32, 113, 103, unchecked((byte)-92), 45, 43, 9, 91, unchecked((byte)-53), unchecked((byte)-101), 37, unchecked((byte)-48), unchecked((byte)-66), unchecked((byte)-27), 108, 82, 89, unchecked((byte)-90), 116, unchecked((byte)-46), unchecked((byte)-26), unchecked((byte)-12), unchecked((byte)-76), unchecked((byte)-64), unchecked((byte)-47), 102, unchecked((byte)-81), unchecked((byte)-62), 57, 75, 99, unchecked((byte)-74)};


		private static readonly byte[] inversePI = new byte[]{unchecked((byte)-91), 45, 50, unchecked((byte)-113), 14, 48, 56, unchecked((byte)-64), 84, unchecked((byte)-26), unchecked((byte)-98), 57, 85, 126, 82, unchecked((byte)-111), 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, unchecked((byte)-88), unchecked((byte)-47), 41, unchecked((byte)-58), unchecked((byte)-92), 63, unchecked((byte)-32), 39, unchecked((byte)-115), 12, unchecked((byte)-126), unchecked((byte)-22), unchecked((byte)-82), unchecked((byte)-76), unchecked((byte)-102), 99, 73, unchecked((byte)-27), 66, unchecked((byte)-28), 21, unchecked((byte)-73), unchecked((byte)-56), 6, 112, unchecked((byte)-99), 65, 117, 25, unchecked((byte)-55), unchecked((byte)-86), unchecked((byte)-4), 77, unchecked((byte)-65), 42, 115, unchecked((byte)-124), unchecked((byte)-43), unchecked((byte)-61), unchecked((byte)-81), 43, unchecked((byte)-122), unchecked((byte)-89), unchecked((byte)-79), unchecked((byte)-78), 91, 70, unchecked((byte)-45), unchecked((byte)-97), unchecked((byte)-3), unchecked((byte)-44), 15, unchecked((byte)-100), 47, unchecked((byte)-101), 67, unchecked((byte)-17), unchecked((byte)-39), 121, unchecked((byte)-74), 83, 127, unchecked((byte)-63), unchecked((byte)-16), 35, unchecked((byte)-25), 37, 94, unchecked((byte)-75), 30, unchecked((byte)-94), unchecked((byte)-33), unchecked((byte)-90), unchecked((byte)-2), unchecked((byte)-84), 34, unchecked((byte)-7), unchecked((byte)-30), 74, unchecked((byte)-68), 53, unchecked((byte)-54), unchecked((byte)-18), 120, 5, 107, 81, unchecked((byte)-31), 89, unchecked((byte)-93), unchecked((byte)-14), 113, 86, 17, 106, unchecked((byte)-119), unchecked((byte)-108), 101, unchecked((byte)-116), unchecked((byte)-69), 119, 60, 123, 40, unchecked((byte)-85), unchecked((byte)-46), 49, unchecked((byte)-34), unchecked((byte)-60), 95, unchecked((byte)-52), unchecked((byte)-49), 118, 44, unchecked((byte)-72), unchecked((byte)-40), 46, 54, unchecked((byte)-37), 105, unchecked((byte)-77), 20, unchecked((byte)-107), unchecked((byte)-66), 98, unchecked((byte)-95), 59, 22, 102, unchecked((byte)-23), 92, 108, 109, unchecked((byte)-83), 55, 97, 75, unchecked((byte)-71), unchecked((byte)-29), unchecked((byte)-70), unchecked((byte)-15), unchecked((byte)-96), unchecked((byte)-123), unchecked((byte)-125), unchecked((byte)-38), 71, unchecked((byte)-59), unchecked((byte)-80), 51, unchecked((byte)-6), unchecked((byte)-106), 111, 110, unchecked((byte)-62), unchecked((byte)-10), 80, unchecked((byte)-1), 93, unchecked((byte)-87), unchecked((byte)-114), 23, 27, unchecked((byte)-105), 125, unchecked((byte)-20), 88, unchecked((byte)-9), 31, unchecked((byte)-5), 124, 9, 13, 122, 103, 69, unchecked((byte)-121), unchecked((byte)-36), unchecked((byte)-24), 79, 29, 78, 4, unchecked((byte)-21), unchecked((byte)-8), unchecked((byte)-13), 62, 61, unchecked((byte)-67), unchecked((byte)-118), unchecked((byte)-120), unchecked((byte)-35), unchecked((byte)-51), 11, 19, unchecked((byte)-104), 2, unchecked((byte)-109), unchecked((byte)-128), unchecked((byte)-112), unchecked((byte)-48), 36, 52, unchecked((byte)-53), unchecked((byte)-19), unchecked((byte)-12), unchecked((byte)-50), unchecked((byte)-103), 16, 68, 64, unchecked((byte)-110), 58, 1, 38, 18, 26, 72, 104, unchecked((byte)-11), unchecked((byte)-127), unchecked((byte)-117), unchecked((byte)-57), unchecked((byte)-42), 32, 10, 8, 0, 76, unchecked((byte)-41), 116};


		private readonly byte[] lFactors = new byte[] {unchecked((byte) -108), 32, unchecked((byte)-123), 16, unchecked((byte)-62), unchecked((byte)-64), 1, unchecked((byte)-5), 1, unchecked((byte)-64), unchecked((byte)-62), 16, unchecked((byte)-123), 32, unchecked((byte)-108), 1};


		protected internal const int BLOCK_SIZE = 16;
		private int KEY_LENGTH = 32;
		private int SUB_LENGTH;
		private byte[][] subKeys = null;
		private bool forEncryption;
		private byte[][] _gf_mul = init_gf256_mul_table();


		private static byte[][] init_gf256_mul_table()
		{
			byte[][] mul_table = new byte[256][];
			for (int x = 0; x < 256; x++)
			{
				mul_table[x] = new byte[256];
				for (int y = 0; y < 256; y++)
				{
					mul_table[x][y] = kuz_mul_gf256_slow((byte)x, (byte)y);
				}
			}
			return mul_table;
		}

		private static byte kuz_mul_gf256_slow(byte a, byte b)
		{
			byte p = 0;
			byte counter;
			byte hi_bit_set;
			for (counter = 0; counter < 8 && a != 0 && b != 0; counter++)
			{
				if ((b & 1) != 0)
				{
					p ^= a;
				}
				hi_bit_set = unchecked((byte)(a & 0x80));
				a <<= 1;
				if (hi_bit_set != 0)
				{
					a ^= unchecked(0xc3); // x^8 + x^7 + x^6 + x + 1
				}
				b >>= 1;
			}
			return p;
		}

		public virtual string getAlgorithmName()
		{
			return "GOST3412_2015";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{

			if (@params is KeyParameter)
			{
				this.forEncryption = forEncryption;
				generateSubKeys(((KeyParameter)@params).getKey());
			}
			else if (@params != null)
			{
				throw new IllegalArgumentException("invalid parameter passed to GOST3412_2015 init - " + @params.GetType().getName());
			}
		}

		private void generateSubKeys(byte[] userKey)
		{

			if (userKey.Length != KEY_LENGTH)
			{
				throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
			}

			subKeys = new byte[10][];
			for (int i = 0; i < 10; i++)
			{
				subKeys[i] = new byte[SUB_LENGTH];
			}

			byte[] x = new byte[SUB_LENGTH];
			byte[] y = new byte[SUB_LENGTH];


			for (int i = 0; i < SUB_LENGTH; i++)
			{
				subKeys[0][i] = x[i] = userKey[i];
				subKeys[1][i] = y[i] = userKey[i + SUB_LENGTH];
			}

			byte[] c = new byte[SUB_LENGTH];

			for (int k = 1; k < 5; k++)
			{

				for (int j = 1; j <= 8; j++)
				{
					C(c, 8 * (k - 1) + j);
					F(c, x, y);
				}

				JavaSystem.arraycopy(x, 0, subKeys[2 * k], 0, SUB_LENGTH);
				JavaSystem.arraycopy(y, 0, subKeys[2 * k + 1], 0, SUB_LENGTH);
			}
		}


		private void C(byte[] c, int i)
		{

			Arrays.clear(c);
			c[15] = (byte)i;
			L(c);
		}


		private void F(byte[] k, byte[] a1, byte[] a0)
		{

			byte[] temp = LSX(k, a1);
			X(temp, a0);

			JavaSystem.arraycopy(a1, 0, a0, 0, SUB_LENGTH);
			JavaSystem.arraycopy(temp, 0, a1, 0, SUB_LENGTH);

		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			if (subKeys == null)
			{
				throw new IllegalStateException("GOST3412_2015 engine not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			GOST3412_2015Func(@in, inOff, @out, outOff);

			return BLOCK_SIZE;
		}


		private void GOST3412_2015Func(byte[] @in, int inOff, byte[] @out, int outOff)
		{

			byte[] block = new byte[BLOCK_SIZE];
			JavaSystem.arraycopy(@in, inOff, block, 0, BLOCK_SIZE);

			if (forEncryption)
			{

				for (int i = 0; i < 9; i++)
				{

					byte[] temp = LSX(subKeys[i], block);
					block = Arrays.copyOf(temp, BLOCK_SIZE);
				}

				X(block, subKeys[9]);
			}
			else
			{

				for (int i = 9; i > 0; i--)
				{

					byte[] temp = XSL(subKeys[i], block);
					block = Arrays.copyOf(temp, BLOCK_SIZE);
				}
				X(block, subKeys[0]);
			}


			JavaSystem.arraycopy(block, 0, @out, outOff, BLOCK_SIZE);
		}

		private byte[] LSX(byte[] k, byte[] a)
		{

			byte[] result = Arrays.copyOf(k, k.Length);
			X(result, a);
			S(result);
			L(result);
			return result;
		}

		private byte[] XSL(byte[] k, byte[] a)
		{
			byte[] result = Arrays.copyOf(k, k.Length);
			X(result, a);
			inverseL(result);
			inverseS(result);
			return result;
		}

		private void X(byte[] result, byte[] data)
		{
			for (int i = 0; i < result.Length; i++)
			{
				result[i] ^= data[i];
			}
		}

		private void S(byte[] data)
		{
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = PI[unsignedByte(data[i])];
			}
		}

		private void inverseS(byte[] data)
		{
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = inversePI[unsignedByte(data[i])];
			}
		}

		private int unsignedByte(byte b)
		{
			return b & 0xFF;
		}

		private void L(byte[] data)
		{
			for (int i = 0; i < 16; i++)
			{
				R(data);
			}
		}

		private void inverseL(byte[] data)
		{
			for (int i = 0; i < 16; i++)
			{
				inverseR(data);
			}
		}


		private void R(byte[] data)
		{
			byte z = l(data);
			JavaSystem.arraycopy(data, 0, data, 1, 15);
			data[0] = z;
		}

		private void inverseR(byte[] data)
		{
			byte[] temp = new byte[16];
			JavaSystem.arraycopy(data, 1, temp, 0, 15);
			temp[15] = data[0];
			byte z = l(temp);
			JavaSystem.arraycopy(data, 1, data, 0, 15);
			data[15] = z;
		}


		private byte l(byte[] data)
		{
			byte x = data[15];
			for (int i = 14; i >= 0; i--)
			{
				x ^= _gf_mul[unsignedByte(data[i])][unsignedByte(lFactors[i])];
			}
			return x;
		}

		public virtual void reset()
		{

		}
	}

}