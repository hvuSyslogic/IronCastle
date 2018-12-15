using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

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


		private static readonly sbyte[] PI = new sbyte[] {(sbyte)-4, (sbyte)-18, (sbyte)-35, 17, (sbyte)-49, 110, 49, 22, (sbyte)-5, (sbyte)-60, (sbyte)-6, (sbyte)-38, 35, (sbyte)-59, 4, 77, (byte)-23, 119, (byte)-16, (byte)-37, (byte)-109, 46, (byte)-103, (byte)-70, 23, 54, (byte)-15, (byte)-69, 20, (byte)-51, 95, (byte)-63, (byte)-7, 24, 101, 90, (byte)-30, 92, (byte)-17, 33, (byte)-127, 28, 60, 66, (byte)-117, 1, (byte)-114, 79, 5, (byte)-124, 2, (byte)-82, (byte)-29, 106, (byte)-113, (byte)-96, 6, 11, (byte)-19, (byte)-104, 127, (byte)-44, (byte)-45, 31, (byte)-21, 52, 44, 81, (byte)-22, (byte)-56, 72, (byte)-85, (byte)-14, 42, 104, (byte)-94, (byte)-3, 58, (byte)-50, (byte)-52, (byte)-75, 112, 14, 86, 8, 12, 118, 18, (byte)-65, 114, 19, 71, (byte)-100, (byte)-73, 93, (byte)-121, 21, (byte)-95, (byte)-106, 41, 16, 123, (byte)-102, (byte)-57, (byte)-13, (byte)-111, 120, 111, (byte)-99, (byte)-98, (byte)-78, (byte)-79, 50, 117, 25, 61, (byte)-1, 53, (byte)-118, 126, 109, 84, (byte)-58, (byte)-128, (byte)-61, (byte)-67, 13, 87, (byte)-33, (byte)-11, 36, (byte)-87, 62, (byte)-88, 67, (byte)-55, (byte)-41, 121, (byte)-42, (byte)-10, 124, 34, (byte)-71, 3, (byte)-32, 15, (byte)-20, (byte)-34, 122, (byte)-108, (byte)-80, (byte)-68, (byte)-36, (byte)-24, 40, 80, 78, 51, 10, 74, (byte)-89, (byte)-105, 96, 115, 30, 0, 98, 68, 26, (byte)-72, 56, (byte)-126, 100, (byte)-97, 38, 65, (byte)-83, 69, 70, (byte)-110, 39, 94, 85, 47, (byte)-116, (byte)-93, (byte)-91, 125, 105, (byte)-43, (byte)-107, 59, 7, 88, (byte)-77, 64, (byte)-122, (byte)-84, 29, (byte)-9, 48, 55, 107, (byte)-28, (byte)-120, (byte)-39, (byte)-25, (byte)-119, (byte)-31, 27, (byte)-125, 73, 76, 63, (byte)-8, (byte)-2, (byte)-115, 83, (byte)-86, (byte)-112, (byte)-54, (byte)-40, (byte)-123, 97, 32, 113, 103, (byte)-92, 45, 43, 9, 91, (byte)-53, (byte)-101, 37, (byte)-48, (byte)-66, (byte)-27, 108, 82, 89, (byte)-90, 116, (byte)-46, (byte)-26, (byte)-12, (byte)-76, (byte)-64, (byte)-47, 102, (byte)-81, (byte)-62, 57, 75, 99, (byte)-74};


		private static readonly sbyte[] inversePI = new sbyte[]{(sbyte)-91, 45, 50, (sbyte)-113, 14, 48, 56, (sbyte)-64, 84, (sbyte)-26, (sbyte)-98, 57, 85, 126, 82, (sbyte)-111, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, (byte)-88, (byte)-47, 41, (byte)-58, (byte)-92, 63, (byte)-32, 39, (byte)-115, 12, (byte)-126, (byte)-22, (byte)-82, (byte)-76, (byte)-102, 99, 73, (byte)-27, 66, (byte)-28, 21, (byte)-73, (byte)-56, 6, 112, (byte)-99, 65, 117, 25, (byte)-55, (byte)-86, (byte)-4, 77, (byte)-65, 42, 115, (byte)-124, (byte)-43, (byte)-61, (byte)-81, 43, (byte)-122, (byte)-89, (byte)-79, (byte)-78, 91, 70, (byte)-45, (byte)-97, (byte)-3, (byte)-44, 15, (byte)-100, 47, (byte)-101, 67, (byte)-17, (byte)-39, 121, (byte)-74, 83, 127, (byte)-63, (byte)-16, 35, (byte)-25, 37, 94, (byte)-75, 30, (byte)-94, (byte)-33, (byte)-90, (byte)-2, (byte)-84, 34, (byte)-7, (byte)-30, 74, (byte)-68, 53, (byte)-54, (byte)-18, 120, 5, 107, 81, (byte)-31, 89, (byte)-93, (byte)-14, 113, 86, 17, 106, (byte)-119, (byte)-108, 101, (byte)-116, (byte)-69, 119, 60, 123, 40, (byte)-85, (byte)-46, 49, (byte)-34, (byte)-60, 95, (byte)-52, (byte)-49, 118, 44, (byte)-72, (byte)-40, 46, 54, (byte)-37, 105, (byte)-77, 20, (byte)-107, (byte)-66, 98, (byte)-95, 59, 22, 102, (byte)-23, 92, 108, 109, (byte)-83, 55, 97, 75, (byte)-71, (byte)-29, (byte)-70, (byte)-15, (byte)-96, (byte)-123, (byte)-125, (byte)-38, 71, (byte)-59, (byte)-80, 51, (byte)-6, (byte)-106, 111, 110, (byte)-62, (byte)-10, 80, (byte)-1, 93, (byte)-87, (byte)-114, 23, 27, (byte)-105, 125, (byte)-20, 88, (byte)-9, 31, (byte)-5, 124, 9, 13, 122, 103, 69, (byte)-121, (byte)-36, (byte)-24, 79, 29, 78, 4, (byte)-21, (byte)-8, (byte)-13, 62, 61, (byte)-67, (byte)-118, (byte)-120, (byte)-35, (byte)-51, 11, 19, (byte)-104, 2, (byte)-109, (byte)-128, (byte)-112, (byte)-48, 36, 52, (byte)-53, (byte)-19, (byte)-12, (byte)-50, (byte)-103, 16, 68, 64, (byte)-110, 58, 1, 38, 18, 26, 72, 104, (byte)-11, (byte)-127, (byte)-117, (byte)-57, (byte)-42, 32, 10, 8, 0, 76, (byte)-41, 116};


		private readonly sbyte[] lFactors = new sbyte[] {-108, 32, -123, 16, -62, -64, 1, -5, 1, -64, -62, 16, -123, 32, -108, 1};


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
					a ^= unchecked((byte)0xc3); // x^8 + x^7 + x^6 + x + 1
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

		private void S(sbyte[] data)
		{
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = PI[unsignedByte(data[i])];
			}
		}

		private void inverseS(sbyte[] data)
		{
			for (int i = 0; i < data.Length; i++)
			{
				data[i] = inversePI[unsignedByte(data[i])];
			}
		}

		private int unsignedByte(sbyte b)
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


		private sbyte l(sbyte[] data)
		{
			sbyte x = data[15];
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