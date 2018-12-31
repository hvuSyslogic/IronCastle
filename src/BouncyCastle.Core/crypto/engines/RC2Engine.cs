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
		private static byte[] piTable = new byte[] {unchecked(0xd9), 0x78, unchecked(0xf9), unchecked(0xc4), 0x19, unchecked(0xdd), unchecked(0xb5), unchecked(0xed), 0x28, unchecked(0xe9), unchecked(0xfd), 0x79, 0x4a, unchecked(0xa0), unchecked(0xd8), unchecked(0x9d), unchecked(0xc6), 0x7e, 0x37, unchecked(0x83), 0x2b, 0x76, 0x53, unchecked(0x8e), 0x62, 0x4c, 0x64, unchecked(0x88), 0x44, unchecked(0x8b), unchecked(0xfb), unchecked(0xa2), 0x17, unchecked(0x9a), 0x59, unchecked(0xf5), unchecked(0x87), unchecked(0xb3), 0x4f, 0x13, 0x61, 0x45, 0x6d, unchecked(0x8d), 0x9, unchecked(0x81), 0x7d, 0x32, unchecked(0xbd), unchecked(0x8f), 0x40, unchecked(0xeb), unchecked(0x86), unchecked(0xb7), 0x7b, 0xb, unchecked(0xf0), unchecked(0x95), 0x21, 0x22, 0x5c, 0x6b, 0x4e, unchecked(0x82), 0x54, unchecked(0xd6), 0x65, unchecked(0x93), unchecked(0xce), 0x60, unchecked(0xb2), 0x1c, 0x73, 0x56, unchecked(0xc0), 0x14, unchecked(0xa7), unchecked(0x8c), unchecked(0xf1), unchecked(0xdc), 0x12, 0x75, unchecked(0xca), 0x1f, 0x3b, unchecked(0xbe), unchecked(0xe4), unchecked(0xd1), 0x42, 0x3d, unchecked(0xd4), 0x30, unchecked(0xa3), 0x3c, unchecked(0xb6), 0x26, 0x6f, unchecked(0xbf), 0xe, unchecked(0xda), 0x46, 0x69, 0x7, 0x57, 0x27, unchecked(0xf2), 0x1d, unchecked(0x9b), unchecked(0xbc), unchecked(0x94), 0x43, 0x3, unchecked(0xf8), 0x11, unchecked(0xc7), unchecked(0xf6), unchecked(0x90), unchecked(0xef), 0x3e, unchecked(0xe7), 0x6, unchecked(0xc3), unchecked(0xd5), 0x2f, unchecked(0xc8), 0x66, 0x1e, unchecked(0xd7), 0x8, unchecked(0xe8), unchecked(0xea), unchecked(0xde), unchecked(0x80), 0x52, unchecked(0xee), unchecked(0xf7), unchecked(0x84), unchecked(0xaa), 0x72, unchecked(0xac), 0x35, 0x4d, 0x6a, 0x2a, unchecked(0x96), 0x1a, unchecked(0xd2), 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, unchecked(0x9f), unchecked(0xd0), 0x5e, 0x4, 0x18, unchecked(0xa4), unchecked(0xec), unchecked(0xc2), unchecked(0xe0), 0x41, 0x6e, 0xf, 0x51, unchecked(0xcb), unchecked(0xcc), 0x24, unchecked(0x91), unchecked(0xaf), 0x50, unchecked(0xa1), unchecked(0xf4), 0x70, 0x39, unchecked(0x99), 0x7c, 0x3a, unchecked(0x85), 0x23, unchecked(0xb8), unchecked(0xb4), 0x7a, unchecked(0xfc), 0x2, 0x36, 0x5b, 0x25, 0x55, unchecked(0x97), 0x31, 0x2d, 0x5d, unchecked(0xfa), unchecked(0x98), unchecked(0xe3), unchecked(0x8a), unchecked(0x92), unchecked(0xae), 0x5, unchecked(0xdf), 0x29, 0x10, 0x67, 0x6c, unchecked(0xba), unchecked(0xc9), unchecked(0xd3), 0x0, unchecked(0xe6), unchecked(0xcf), unchecked(0xe1), unchecked(0x9e), unchecked(0xa8), 0x2c, 0x63, 0x16, 0x1, 0x3f, 0x58, unchecked(0xe2), unchecked(0x89), unchecked(0xa9), 0xd, 0x38, 0x34, 0x1b, unchecked(0xab), 0x33, unchecked(0xff), unchecked(0xb0), unchecked(0xbb), 0x48, 0xc, 0x5f, unchecked(0xb9), unchecked(0xb1), unchecked(0xcd), 0x2e, unchecked(0xc5), unchecked(0xf3), unchecked(0xdb), 0x47, unchecked(0xe5), unchecked(0xa5), unchecked(0x9c), 0x77, 0xa, unchecked(0xa6), 0x20, 0x68, unchecked(0xfe), 0x7f, unchecked(0xc1), unchecked(0xad)};

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