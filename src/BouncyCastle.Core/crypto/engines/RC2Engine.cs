using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;

	/// <summary>
	/// an implementation of RC2 as described in RFC 2268
	///      "A Description of the RC2(r) Encryption Algorithm" R. Rivest.
	/// </summary>
	public class RC2Engine : BlockCipher
	{
		//
		// the values we use for key expansion (based on the digits of PI)
		//
		private static byte[] piTable = new byte[] {unchecked((byte)0xd9), (byte)0x78, unchecked((byte)0xf9), unchecked((byte)0xc4), (byte)0x19, unchecked((byte)0xdd), unchecked((byte)0xb5), unchecked((byte)0xed), (byte)0x28, unchecked((byte)0xe9), unchecked((byte)0xfd), (byte)0x79, (byte)0x4a, unchecked((byte)0xa0), unchecked((byte)0xd8), unchecked((byte)0x9d), unchecked((byte)0xc6), (byte)0x7e, (byte)0x37, unchecked((byte)0x83), (byte)0x2b, (byte)0x76, (byte)0x53, unchecked((byte)0x8e), (byte)0x62, (byte)0x4c, (byte)0x64, unchecked((byte)0x88), (byte)0x44, unchecked((byte)0x8b), unchecked((byte)0xfb), unchecked((byte)0xa2), (byte)0x17, unchecked((byte)0x9a), (byte)0x59, unchecked((byte)0xf5), unchecked((byte)0x87), unchecked((byte)0xb3), (byte)0x4f, (byte)0x13, (byte)0x61, (byte)0x45, (byte)0x6d, unchecked((byte)0x8d), (byte)0x9, unchecked((byte)0x81), (byte)0x7d, (byte)0x32, unchecked((byte)0xbd), unchecked((byte)0x8f), (byte)0x40, unchecked((byte)0xeb), unchecked((byte)0x86), unchecked((byte)0xb7), (byte)0x7b, (byte)0xb, unchecked((byte)0xf0), unchecked((byte)0x95), (byte)0x21, (byte)0x22, (byte)0x5c, (byte)0x6b, (byte)0x4e, unchecked((byte)0x82), (byte)0x54, unchecked((byte)0xd6), (byte)0x65, unchecked((byte)0x93), unchecked((byte)0xce), (byte)0x60, unchecked((byte)0xb2), (byte)0x1c, (byte)0x73, (byte)0x56, unchecked((byte)0xc0), (byte)0x14, unchecked((byte)0xa7), unchecked((byte)0x8c), unchecked((byte)0xf1), unchecked((byte)0xdc), (byte)0x12, (byte)0x75, unchecked((byte)0xca), (byte)0x1f, (byte)0x3b, unchecked((byte)0xbe), unchecked((byte)0xe4), unchecked((byte)0xd1), (byte)0x42, (byte)0x3d, unchecked((byte)0xd4), (byte)0x30, unchecked((byte)0xa3), (byte)0x3c, unchecked((byte)0xb6), (byte)0x26, (byte)0x6f, unchecked((byte)0xbf), (byte)0xe, unchecked((byte)0xda), (byte)0x46, (byte)0x69, (byte)0x7, (byte)0x57, (byte)0x27, unchecked((byte)0xf2), (byte)0x1d, unchecked((byte)0x9b), unchecked((byte)0xbc), unchecked((byte)0x94), (byte)0x43, (byte)0x3, unchecked((byte)0xf8), (byte)0x11, unchecked((byte)0xc7), unchecked((byte)0xf6), unchecked((byte)0x90), unchecked((byte)0xef), (byte)0x3e, unchecked((byte)0xe7), (byte)0x6, unchecked((byte)0xc3), unchecked((byte)0xd5), (byte)0x2f, unchecked((byte)0xc8), (byte)0x66, (byte)0x1e, unchecked((byte)0xd7), (byte)0x8, unchecked((byte)0xe8), unchecked((byte)0xea), unchecked((byte)0xde), unchecked((byte)0x80), (byte)0x52, unchecked((byte)0xee), unchecked((byte)0xf7), unchecked((byte)0x84), unchecked((byte)0xaa), (byte)0x72, unchecked((byte)0xac), (byte)0x35, (byte)0x4d, (byte)0x6a, (byte)0x2a, unchecked((byte)0x96), (byte)0x1a, unchecked((byte)0xd2), (byte)0x71, (byte)0x5a, (byte)0x15, (byte)0x49, (byte)0x74, (byte)0x4b, unchecked((byte)0x9f), unchecked((byte)0xd0), (byte)0x5e, (byte)0x4, (byte)0x18, unchecked((byte)0xa4), unchecked((byte)0xec), unchecked((byte)0xc2), unchecked((byte)0xe0), (byte)0x41, (byte)0x6e, (byte)0xf, (byte)0x51, unchecked((byte)0xcb), unchecked((byte)0xcc), (byte)0x24, unchecked((byte)0x91), unchecked((byte)0xaf), (byte)0x50, unchecked((byte)0xa1), unchecked((byte)0xf4), (byte)0x70, (byte)0x39, unchecked((byte)0x99), (byte)0x7c, (byte)0x3a, unchecked((byte)0x85), (byte)0x23, unchecked((byte)0xb8), unchecked((byte)0xb4), (byte)0x7a, unchecked((byte)0xfc), (byte)0x2, (byte)0x36, (byte)0x5b, (byte)0x25, (byte)0x55, unchecked((byte)0x97), (byte)0x31, (byte)0x2d, (byte)0x5d, unchecked((byte)0xfa), unchecked((byte)0x98), unchecked((byte)0xe3), unchecked((byte)0x8a), unchecked((byte)0x92), unchecked((byte)0xae), (byte)0x5, unchecked((byte)0xdf), (byte)0x29, (byte)0x10, (byte)0x67, (byte)0x6c, unchecked((byte)0xba), unchecked((byte)0xc9), unchecked((byte)0xd3), (byte)0x0, unchecked((byte)0xe6), unchecked((byte)0xcf), unchecked((byte)0xe1), unchecked((byte)0x9e), unchecked((byte)0xa8), (byte)0x2c, (byte)0x63, (byte)0x16, (byte)0x1, (byte)0x3f, (byte)0x58, unchecked((byte)0xe2), unchecked((byte)0x89), unchecked((byte)0xa9), (byte)0xd, (byte)0x38, (byte)0x34, (byte)0x1b, unchecked((byte)0xab), (byte)0x33, unchecked((byte)0xff), unchecked((byte)0xb0), unchecked((byte)0xbb), (byte)0x48, (byte)0xc, (byte)0x5f, unchecked((byte)0xb9), unchecked((byte)0xb1), unchecked((byte)0xcd), (byte)0x2e, unchecked((byte)0xc5), unchecked((byte)0xf3), unchecked((byte)0xdb), (byte)0x47, unchecked((byte)0xe5), unchecked((byte)0xa5), unchecked((byte)0x9c), (byte)0x77, (byte)0xa, unchecked((byte)0xa6), (byte)0x20, (byte)0x68, unchecked((byte)0xfe), (byte)0x7f, unchecked((byte)0xc1), unchecked((byte)0xad)};

		private const int BLOCK_SIZE = 8;

		private int[] workingKey;
		private bool encrypting;

		private int[] generateWorkingKey(byte[] key, int bits)
		{
			int x;
			int[] xKey = new int[128];

			for (int i = 0; i != key.Length; i++)
			{
				xKey[i] = key[i] & 0xff;
			}

			// Phase 1: Expand input key to 128 bytes
			int len = key.Length;

			if (len < 128)
			{
				int index = 0;

				x = xKey[len - 1];

				do
				{
					x = piTable[(x + xKey[index++]) & 255] & 0xff;
					xKey[len++] = x;
				} while (len < 128);
			}

			// Phase 2 - reduce effective key size to "bits"
			len = (bits + 7) >> 3;
			x = piTable[xKey[128 - len] & (255 >> (7 & -bits))] & 0xff;
			xKey[128 - len] = x;

			for (int i = 128 - len - 1; i >= 0; i--)
			{
					x = piTable[x ^ xKey[i + len]] & 0xff;
					xKey[i] = x;
			}

			// Phase 3 - copy to newKey in little-endian order 
			int[] newKey = new int[64];

			for (int i = 0; i != newKey.Length; i++)
			{
				newKey[i] = (xKey[2 * i] + (xKey[2 * i + 1] << 8));
			}

			return newKey;
		}

		/// <summary>
		/// initialise a RC2 cipher.
		/// </summary>
		/// <param name="encrypting"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool encrypting, CipherParameters @params)
		{
			this.encrypting = encrypting;

			if (@params is RC2Parameters)
			{
				RC2Parameters param = (RC2Parameters)@params;

				workingKey = generateWorkingKey(param.getKey(), param.getEffectiveKeyBits());
			}
			else if (@params is KeyParameter)
			{
				byte[] key = ((KeyParameter)@params).getKey();

				workingKey = generateWorkingKey(key, key.Length * 8);
			}
			else
			{
				throw new IllegalArgumentException("invalid parameter passed to RC2 init - " + @params.GetType().getName());
			}

		}

		public virtual void reset()
		{
		}

		public virtual string getAlgorithmName()
		{
			return "RC2";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("RC2 engine not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (encrypting)
			{
				encryptBlock(@in, inOff, @out, outOff);
			}
			else
			{
				decryptBlock(@in, inOff, @out, outOff);
			}

			return BLOCK_SIZE;
		}

		/// <summary>
		/// return the result rotating the 16 bit number in x left by y
		/// </summary>
		private int rotateWordLeft(int x, int y)
		{
			x &= 0xffff;
			return (x << y) | (x >> (16 - y));
		}

		private void encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			int x76, x54, x32, x10;

			x76 = ((@in[inOff + 7] & 0xff) << 8) + (@in[inOff + 6] & 0xff);
			x54 = ((@in[inOff + 5] & 0xff) << 8) + (@in[inOff + 4] & 0xff);
			x32 = ((@in[inOff + 3] & 0xff) << 8) + (@in[inOff + 2] & 0xff);
			x10 = ((@in[inOff + 1] & 0xff) << 8) + (@in[inOff + 0] & 0xff);

			for (int i = 0; i <= 16; i += 4)
			{
					x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
					x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
					x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
					x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
			}

			x10 += workingKey[x76 & 63];
			x32 += workingKey[x10 & 63];
			x54 += workingKey[x32 & 63];
			x76 += workingKey[x54 & 63];

			for (int i = 20; i <= 40; i += 4)
			{
					x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
					x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
					x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
					x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
			}

			x10 += workingKey[x76 & 63];
			x32 += workingKey[x10 & 63];
			x54 += workingKey[x32 & 63];
			x76 += workingKey[x54 & 63];

			for (int i = 44; i < 64; i += 4)
			{
					x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
					x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
					x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
					x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
			}

			@out[outOff + 0] = (byte)x10;
			@out[outOff + 1] = (byte)(x10 >> 8);
			@out[outOff + 2] = (byte)x32;
			@out[outOff + 3] = (byte)(x32 >> 8);
			@out[outOff + 4] = (byte)x54;
			@out[outOff + 5] = (byte)(x54 >> 8);
			@out[outOff + 6] = (byte)x76;
			@out[outOff + 7] = (byte)(x76 >> 8);
		}

		private void decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			int x76, x54, x32, x10;

			x76 = ((@in[inOff + 7] & 0xff) << 8) + (@in[inOff + 6] & 0xff);
			x54 = ((@in[inOff + 5] & 0xff) << 8) + (@in[inOff + 4] & 0xff);
			x32 = ((@in[inOff + 3] & 0xff) << 8) + (@in[inOff + 2] & 0xff);
			x10 = ((@in[inOff + 1] & 0xff) << 8) + (@in[inOff + 0] & 0xff);

			for (int i = 60; i >= 44; i -= 4)
			{
				x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
				x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
				x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
				x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
			}

			x76 -= workingKey[x54 & 63];
			x54 -= workingKey[x32 & 63];
			x32 -= workingKey[x10 & 63];
			x10 -= workingKey[x76 & 63];

			for (int i = 40; i >= 20; i -= 4)
			{
				x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
				x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
				x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
				x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
			}

			x76 -= workingKey[x54 & 63];
			x54 -= workingKey[x32 & 63];
			x32 -= workingKey[x10 & 63];
			x10 -= workingKey[x76 & 63];

			for (int i = 16; i >= 0; i -= 4)
			{
				x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
				x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
				x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
				x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
			}

			@out[outOff + 0] = (byte)x10;
			@out[outOff + 1] = (byte)(x10 >> 8);
			@out[outOff + 2] = (byte)x32;
			@out[outOff + 3] = (byte)(x32 >> 8);
			@out[outOff + 4] = (byte)x54;
			@out[outOff + 5] = (byte)(x54 >> 8);
			@out[outOff + 6] = (byte)x76;
			@out[outOff + 7] = (byte)(x76 >> 8);
		}
	}

}