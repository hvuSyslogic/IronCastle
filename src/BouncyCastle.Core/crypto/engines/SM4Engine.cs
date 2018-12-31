using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// SM4 Block Cipher - SM4 is a 128 bit block cipher with a 128 bit key.
	/// <para>
	///     The implementation here is based on the document <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
	///     by Whitfield Diffie and George Ledin, which is a translation of Prof. LU Shu-wang's original standard.
	/// </para>
	/// </summary>
	public class SM4Engine : BlockCipher
	{
		private const int BLOCK_SIZE = 16;

		private static readonly byte[] Sbox = new byte[] {unchecked(0xd6), unchecked(0x90), unchecked(0xe9), unchecked(0xfe), unchecked(0xcc), unchecked(0xe1), 0x3d, unchecked(0xb7), 0x16, unchecked(0xb6), 0x14, unchecked(0xc2), 0x28, unchecked(0xfb), 0x2c, 0x05, 0x2b, 0x67, unchecked(0x9a), 0x76, 0x2a, unchecked(0xbe), 0x04, unchecked(0xc3), unchecked(0xaa), 0x44, 0x13, 0x26, 0x49, unchecked(0x86), 0x06, unchecked(0x99), unchecked(0x9c), 0x42, 0x50, unchecked(0xf4), unchecked(0x91), unchecked(0xef), unchecked(0x98), 0x7a, 0x33, 0x54, 0x0b, 0x43, unchecked(0xed), unchecked(0xcf), unchecked(0xac), 0x62, unchecked(0xe4), unchecked(0xb3), 0x1c, unchecked(0xa9), unchecked(0xc9), 0x08, unchecked(0xe8), unchecked(0x95), unchecked(0x80), unchecked(0xdf), unchecked(0x94), unchecked(0xfa), 0x75, unchecked(0x8f), 0x3f, unchecked(0xa6), 0x47, 0x07, unchecked(0xa7), unchecked(0xfc), unchecked(0xf3), 0x73, 0x17, unchecked(0xba), unchecked(0x83), 0x59, 0x3c, 0x19, unchecked(0xe6), unchecked(0x85), 0x4f, unchecked(0xa8), 0x68, 0x6b, unchecked(0x81), unchecked(0xb2), 0x71, 0x64, unchecked(0xda), unchecked(0x8b), unchecked(0xf8), unchecked(0xeb), 0x0f, 0x4b, 0x70, 0x56, unchecked(0x9d), 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, unchecked(0xd1), unchecked(0xa2), 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, unchecked(0x87), unchecked(0xd4), 0x00, 0x46, 0x57, unchecked(0x9f), unchecked(0xd3), 0x27, 0x52, 0x4c, 0x36, 0x02, unchecked(0xe7), unchecked(0xa0), unchecked(0xc4), unchecked(0xc8), unchecked(0x9e), unchecked(0xea), unchecked(0xbf), unchecked(0x8a), unchecked(0xd2), 0x40, unchecked(0xc7), 0x38, unchecked(0xb5), unchecked(0xa3), unchecked(0xf7), unchecked(0xf2), unchecked(0xce), unchecked(0xf9), 0x61, 0x15, unchecked(0xa1), unchecked(0xe0), unchecked(0xae), 0x5d, unchecked(0xa4), unchecked(0x9b), 0x34, 0x1a, 0x55, unchecked(0xad), unchecked(0x93), 0x32, 0x30, unchecked(0xf5), unchecked(0x8c), unchecked(0xb1), unchecked(0xe3), 0x1d, unchecked(0xf6), unchecked(0xe2), 0x2e, unchecked(0x82), 0x66, unchecked(0xca), 0x60, unchecked(0xc0), 0x29, 0x23, unchecked(0xab), 0x0d, 0x53, 0x4e, 0x6f, unchecked(0xd5), unchecked(0xdb), 0x37, 0x45, unchecked(0xde), unchecked(0xfd), unchecked(0x8e), 0x2f, 0x03, unchecked(0xff), 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, unchecked(0x8d), 0x1b, unchecked(0xaf), unchecked(0x92), unchecked(0xbb), unchecked(0xdd), unchecked(0xbc), 0x7f, 0x11, unchecked(0xd9), 0x5c, 0x41, 0x1f, 0x10, 0x5a, unchecked(0xd8), 0x0a, unchecked(0xc1), 0x31, unchecked(0x88), unchecked(0xa5), unchecked(0xcd), 0x7b, unchecked(0xbd), 0x2d, 0x74, unchecked(0xd0), 0x12, unchecked(0xb8), unchecked(0xe5), unchecked(0xb4), unchecked(0xb0), unchecked(0x89), 0x69, unchecked(0x97), 0x4a, 0x0c, unchecked(0x96), 0x77, 0x7e, 0x65, unchecked(0xb9), unchecked(0xf1), 0x09, unchecked(0xc5), 0x6e, unchecked(0xc6), unchecked(0x84), 0x18, unchecked(0xf0), 0x7d, unchecked(0xec), 0x3a, unchecked(0xdc), 0x4d, 0x20, 0x79, unchecked(0xee), 0x5f, 0x3e, unchecked(0xd7), unchecked(0xcb), 0x39, 0x48};

		private static readonly int[] CK = new int[] {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, unchecked((int)0x8c939aa1), unchecked((int)0xa8afb6bd), unchecked((int)0xc4cbd2d9), unchecked((int)0xe0e7eef5), unchecked((int)0xfc030a11), 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, unchecked((int)0x888f969d), unchecked((int)0xa4abb2b9), unchecked((int)0xc0c7ced5), unchecked((int)0xdce3eaf1), unchecked((int)0xf8ff060d), 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, unchecked((int)0x848b9299), unchecked((int)0xa0a7aeb5), unchecked((int)0xbcc3cad1), unchecked((int)0xd8dfe6ed), unchecked((int)0xf4fb0209), 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

		private static readonly int[] FK = new int[] {unchecked((int)0xa3b1bac6), 0x56aa3350, 0x677d9197, unchecked((int)0xb27022dc)};

		private readonly int[] X = new int[4];

		private int[] rk;

		private int rotateLeft(int x, int bits)
		{
			return (x << bits) | ((int)((uint)x >> -bits));
		}

		// non-linear substitution tau.
		private int tau(int A)
		{
			int b0 = Sbox[(A >> 24) & 0xff] & 0xff;
			int b1 = Sbox[(A >> 16) & 0xff] & 0xff;
			int b2 = Sbox[(A >> 8) & 0xff] & 0xff;
			int b3 = Sbox[A & 0xff] & 0xff;

			return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
		}

		private int L_ap(int B)
		{
			return (B ^ (rotateLeft(B, 13)) ^ (rotateLeft(B, 23)));
		}

		private int T_ap(int Z)
		{
			return L_ap(tau(Z));
		}

		// Key expansion
		private int[] expandKey(bool forEncryption, byte[] key)
		{
			int[] rk = new int[32];
			int[] MK = new int[4];

			MK[0] = Pack.bigEndianToInt(key, 0);
			MK[1] = Pack.bigEndianToInt(key, 4);
			MK[2] = Pack.bigEndianToInt(key, 8);
			MK[3] = Pack.bigEndianToInt(key, 12);

			int i;
			int[] K = new int[4];
			K[0] = MK[0] ^ FK[0];
			K[1] = MK[1] ^ FK[1];
			K[2] = MK[2] ^ FK[2];
			K[3] = MK[3] ^ FK[3];

			if (forEncryption)
			{
				rk[0] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
				rk[1] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[0] ^ CK[1]);
				rk[2] = K[2] ^ T_ap(K[3] ^ rk[0] ^ rk[1] ^ CK[2]);
				rk[3] = K[3] ^ T_ap(rk[0] ^ rk[1] ^ rk[2] ^ CK[3]);
				for (i = 4; i < 32; i++)
				{
					rk[i] = rk[i - 4] ^ T_ap(rk[i - 3] ^ rk[i - 2] ^ rk[i - 1] ^ CK[i]);
				}
			}
			else
			{
				rk[31] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
				rk[30] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[31] ^ CK[1]);
				rk[29] = K[2] ^ T_ap(K[3] ^ rk[31] ^ rk[30] ^ CK[2]);
				rk[28] = K[3] ^ T_ap(rk[31] ^ rk[30] ^ rk[29] ^ CK[3]);
				for (i = 27; i >= 0; i--)
				{
					rk[i] = rk[i + 4] ^ T_ap(rk[i + 3] ^ rk[i + 2] ^ rk[i + 1] ^ CK[31 - i]);
				}
			}

			return rk;
		}


		// Linear substitution L
		private int L(int B)
		{
			int C;
			C = (B ^ (rotateLeft(B, 2)) ^ (rotateLeft(B, 10)) ^ (rotateLeft(B, 18)) ^ (rotateLeft(B, 24)));
			return C;
		}

		// Mixer-substitution T
		private int T(int Z)
		{
			return L(tau(Z));
		}

		// The round functions
		private int F0(int[] X, int rk)
		{
			return (X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ rk));
		}

		private int F1(int[] X, int rk)
		{
			return (X[1] ^ T(X[2] ^ X[3] ^ X[0] ^ rk));
		}

		private int F2(int[] X, int rk)
		{
			return (X[2] ^ T(X[3] ^ X[0] ^ X[1] ^ rk));
		}

		private int F3(int[] X, int rk)
		{
			return (X[3] ^ T(X[0] ^ X[1] ^ X[2] ^ rk));
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				byte[] key = ((KeyParameter)@params).getKey();

				if (key.Length != 16)
				{
					throw new IllegalArgumentException("SM4 requires a 128 bit key");
				}

				rk = expandKey(forEncryption, key);
			}
			else
			{
				throw new IllegalArgumentException("invalid parameter passed to SM4 init - " + @params.GetType().getName());
			}
		}

		public virtual string getAlgorithmName()
		{
			return "SM4";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (rk == null)
			{
				throw new IllegalStateException("SM4 not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			X[0] = Pack.bigEndianToInt(@in, inOff);
			X[1] = Pack.bigEndianToInt(@in, inOff + 4);
			X[2] = Pack.bigEndianToInt(@in, inOff + 8);
			X[3] = Pack.bigEndianToInt(@in, inOff + 12);

			int i;

			for (i = 0; i < 32; i += 4)
			{
				X[0] = F0(X, rk[i]);
				X[1] = F1(X, rk[i + 1]);
				X[2] = F2(X, rk[i + 2]);
				X[3] = F3(X, rk[i + 3]);
			}

			Pack.intToBigEndian(X[3], @out, outOff);
			Pack.intToBigEndian(X[2], @out, outOff + 4);
			Pack.intToBigEndian(X[1], @out, outOff + 8);
			Pack.intToBigEndian(X[0], @out, outOff + 12);

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
		}
	}

}