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

		private static readonly byte[] Sbox = new byte[] {unchecked((byte)0xd6), unchecked((byte)0x90), unchecked((byte)0xe9), unchecked((byte)0xfe), unchecked((byte)0xcc), unchecked((byte)0xe1), (byte)0x3d, unchecked((byte)0xb7), (byte)0x16, unchecked((byte)0xb6), (byte)0x14, unchecked((byte)0xc2), (byte)0x28, unchecked((byte)0xfb), (byte)0x2c, (byte)0x05, (byte)0x2b, (byte)0x67, unchecked((byte)0x9a), (byte)0x76, (byte)0x2a, unchecked((byte)0xbe), (byte)0x04, unchecked((byte)0xc3), unchecked((byte)0xaa), (byte)0x44, (byte)0x13, (byte)0x26, (byte)0x49, unchecked((byte)0x86), (byte)0x06, unchecked((byte)0x99), unchecked((byte)0x9c), (byte)0x42, (byte)0x50, unchecked((byte)0xf4), unchecked((byte)0x91), unchecked((byte)0xef), unchecked((byte)0x98), (byte)0x7a, (byte)0x33, (byte)0x54, (byte)0x0b, (byte)0x43, unchecked((byte)0xed), unchecked((byte)0xcf), unchecked((byte)0xac), (byte)0x62, unchecked((byte)0xe4), unchecked((byte)0xb3), (byte)0x1c, unchecked((byte)0xa9), unchecked((byte)0xc9), (byte)0x08, unchecked((byte)0xe8), unchecked((byte)0x95), unchecked((byte)0x80), unchecked((byte)0xdf), unchecked((byte)0x94), unchecked((byte)0xfa), (byte)0x75, unchecked((byte)0x8f), (byte)0x3f, unchecked((byte)0xa6), (byte)0x47, (byte)0x07, unchecked((byte)0xa7), unchecked((byte)0xfc), unchecked((byte)0xf3), (byte)0x73, (byte)0x17, unchecked((byte)0xba), unchecked((byte)0x83), (byte)0x59, (byte)0x3c, (byte)0x19, unchecked((byte)0xe6), unchecked((byte)0x85), (byte)0x4f, unchecked((byte)0xa8), (byte)0x68, (byte)0x6b, unchecked((byte)0x81), unchecked((byte)0xb2), (byte)0x71, (byte)0x64, unchecked((byte)0xda), unchecked((byte)0x8b), unchecked((byte)0xf8), unchecked((byte)0xeb), (byte)0x0f, (byte)0x4b, (byte)0x70, (byte)0x56, unchecked((byte)0x9d), (byte)0x35, (byte)0x1e, (byte)0x24, (byte)0x0e, (byte)0x5e, (byte)0x63, (byte)0x58, unchecked((byte)0xd1), unchecked((byte)0xa2), (byte)0x25, (byte)0x22, (byte)0x7c, (byte)0x3b, (byte)0x01, (byte)0x21, (byte)0x78, unchecked((byte)0x87), unchecked((byte)0xd4), (byte)0x00, (byte)0x46, (byte)0x57, unchecked((byte)0x9f), unchecked((byte)0xd3), (byte)0x27, (byte)0x52, (byte)0x4c, (byte)0x36, (byte)0x02, unchecked((byte)0xe7), unchecked((byte)0xa0), unchecked((byte)0xc4), unchecked((byte)0xc8), unchecked((byte)0x9e), unchecked((byte)0xea), unchecked((byte)0xbf), unchecked((byte)0x8a), unchecked((byte)0xd2), (byte)0x40, unchecked((byte)0xc7), (byte)0x38, unchecked((byte)0xb5), unchecked((byte)0xa3), unchecked((byte)0xf7), unchecked((byte)0xf2), unchecked((byte)0xce), unchecked((byte)0xf9), (byte)0x61, (byte)0x15, unchecked((byte)0xa1), unchecked((byte)0xe0), unchecked((byte)0xae), (byte)0x5d, unchecked((byte)0xa4), unchecked((byte)0x9b), (byte)0x34, (byte)0x1a, (byte)0x55, unchecked((byte)0xad), unchecked((byte)0x93), (byte)0x32, (byte)0x30, unchecked((byte)0xf5), unchecked((byte)0x8c), unchecked((byte)0xb1), unchecked((byte)0xe3), (byte)0x1d, unchecked((byte)0xf6), unchecked((byte)0xe2), (byte)0x2e, unchecked((byte)0x82), (byte)0x66, unchecked((byte)0xca), (byte)0x60, unchecked((byte)0xc0), (byte)0x29, (byte)0x23, unchecked((byte)0xab), (byte)0x0d, (byte)0x53, (byte)0x4e, (byte)0x6f, unchecked((byte)0xd5), unchecked((byte)0xdb), (byte)0x37, (byte)0x45, unchecked((byte)0xde), unchecked((byte)0xfd), unchecked((byte)0x8e), (byte)0x2f, (byte)0x03, unchecked((byte)0xff), (byte)0x6a, (byte)0x72, (byte)0x6d, (byte)0x6c, (byte)0x5b, (byte)0x51, unchecked((byte)0x8d), (byte)0x1b, unchecked((byte)0xaf), unchecked((byte)0x92), unchecked((byte)0xbb), unchecked((byte)0xdd), unchecked((byte)0xbc), (byte)0x7f, (byte)0x11, unchecked((byte)0xd9), (byte)0x5c, (byte)0x41, (byte)0x1f, (byte)0x10, (byte)0x5a, unchecked((byte)0xd8), (byte)0x0a, unchecked((byte)0xc1), (byte)0x31, unchecked((byte)0x88), unchecked((byte)0xa5), unchecked((byte)0xcd), (byte)0x7b, unchecked((byte)0xbd), (byte)0x2d, (byte)0x74, unchecked((byte)0xd0), (byte)0x12, unchecked((byte)0xb8), unchecked((byte)0xe5), unchecked((byte)0xb4), unchecked((byte)0xb0), unchecked((byte)0x89), (byte)0x69, unchecked((byte)0x97), (byte)0x4a, (byte)0x0c, unchecked((byte)0x96), (byte)0x77, (byte)0x7e, (byte)0x65, unchecked((byte)0xb9), unchecked((byte)0xf1), (byte)0x09, unchecked((byte)0xc5), (byte)0x6e, unchecked((byte)0xc6), unchecked((byte)0x84), (byte)0x18, unchecked((byte)0xf0), (byte)0x7d, unchecked((byte)0xec), (byte)0x3a, unchecked((byte)0xdc), (byte)0x4d, (byte)0x20, (byte)0x79, unchecked((byte)0xee), (byte)0x5f, (byte)0x3e, unchecked((byte)0xd7), unchecked((byte)0xcb), (byte)0x39, (byte)0x48};

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