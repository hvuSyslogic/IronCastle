using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	
	/// <summary>
	/// A class that provides Twofish encryption operations.
	/// 
	/// This Java implementation is based on the Java reference
	/// implementation provided by Bruce Schneier and developed
	/// by Raif S. Naffah.
	/// </summary>
	public sealed class TwofishEngine : BlockCipher
	{
		private static readonly byte[][] P = new byte[][]
		{
			new byte[] {unchecked(0xA9), 0x67, unchecked(0xB3), unchecked(0xE8), 0x04, unchecked(0xFD), unchecked(0xA3), 0x76, unchecked(0x9A), unchecked(0x92), unchecked(0x80), 0x78, unchecked(0xE4), unchecked(0xDD), unchecked(0xD1), 0x38, 0x0D, unchecked(0xC6), 0x35, unchecked(0x98), 0x18, unchecked(0xF7), unchecked(0xEC), 0x6C, 0x43, 0x75, 0x37, 0x26, unchecked(0xFA), 0x13, unchecked(0x94), 0x48, unchecked(0xF2), unchecked(0xD0), unchecked(0x8B), 0x30, unchecked(0x84), 0x54, unchecked(0xDF), 0x23, 0x19, 0x5B, 0x3D, 0x59, unchecked(0xF3), unchecked(0xAE), unchecked(0xA2), unchecked(0x82), 0x63, 0x01, unchecked(0x83), 0x2E, unchecked(0xD9), 0x51, unchecked(0x9B), 0x7C, unchecked(0xA6), unchecked(0xEB), unchecked(0xA5), unchecked(0xBE), 0x16, 0x0C, unchecked(0xE3), 0x61, unchecked(0xC0), unchecked(0x8C), 0x3A, unchecked(0xF5), 0x73, 0x2C, 0x25, 0x0B, unchecked(0xBB), 0x4E, unchecked(0x89), 0x6B, 0x53, 0x6A, unchecked(0xB4), unchecked(0xF1), unchecked(0xE1), unchecked(0xE6), unchecked(0xBD), 0x45, unchecked(0xE2), unchecked(0xF4), unchecked(0xB6), 0x66, unchecked(0xCC), unchecked(0x95), 0x03, 0x56, unchecked(0xD4), 0x1C, 0x1E, unchecked(0xD7), unchecked(0xFB), unchecked(0xC3), unchecked(0x8E), unchecked(0xB5), unchecked(0xE9), unchecked(0xCF), unchecked(0xBF), unchecked(0xBA), unchecked(0xEA), 0x77, 0x39, unchecked(0xAF), 0x33, unchecked(0xC9), 0x62, 0x71, unchecked(0x81), 0x79, 0x09, unchecked(0xAD), 0x24, unchecked(0xCD), unchecked(0xF9), unchecked(0xD8), unchecked(0xE5), unchecked(0xC5), unchecked(0xB9), 0x4D, 0x44, 0x08, unchecked(0x86), unchecked(0xE7), unchecked(0xA1), 0x1D, unchecked(0xAA), unchecked(0xED), 0x06, 0x70, unchecked(0xB2), unchecked(0xD2), 0x41, 0x7B, unchecked(0xA0), 0x11, 0x31, unchecked(0xC2), 0x27, unchecked(0x90), 0x20, unchecked(0xF6), 0x60, unchecked(0xFF), unchecked(0x96), 0x5C, unchecked(0xB1), unchecked(0xAB), unchecked(0x9E), unchecked(0x9C), 0x52, 0x1B, 0x5F, unchecked(0x93), 0x0A, unchecked(0xEF), unchecked(0x91), unchecked(0x85), 0x49, unchecked(0xEE), 0x2D, 0x4F, unchecked(0x8F), 0x3B, 0x47, unchecked(0x87), 0x6D, 0x46, unchecked(0xD6), 0x3E, 0x69, 0x64, 0x2A, unchecked(0xCE), unchecked(0xCB), 0x2F, unchecked(0xFC), unchecked(0x97), 0x05, 0x7A, unchecked(0xAC), 0x7F, unchecked(0xD5), 0x1A, 0x4B, 0x0E, unchecked(0xA7), 0x5A, 0x28, 0x14, 0x3F, 0x29, unchecked(0x88), 0x3C, 0x4C, 0x02, unchecked(0xB8), unchecked(0xDA), unchecked(0xB0), 0x17, 0x55, 0x1F, unchecked(0x8A), 0x7D, 0x57, unchecked(0xC7), unchecked(0x8D), 0x74, unchecked(0xB7), unchecked(0xC4), unchecked(0x9F), 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, unchecked(0x99), 0x34, 0x6E, 0x50, unchecked(0xDE), 0x68, 0x65, unchecked(0xBC), unchecked(0xDB), unchecked(0xF8), unchecked(0xC8), unchecked(0xA8), 0x2B, 0x40, unchecked(0xDC), unchecked(0xFE), 0x32, unchecked(0xA4), unchecked(0xCA), 0x10, 0x21, unchecked(0xF0), unchecked(0xD3), 0x5D, 0x0F, 0x00, 0x6F, unchecked(0x9D), 0x36, 0x42, 0x4A, 0x5E, unchecked(0xC1), unchecked(0xE0)},
			new byte[] {0x75, unchecked(0xF3), unchecked(0xC6), unchecked(0xF4), unchecked(0xDB), 0x7B, unchecked(0xFB), unchecked(0xC8), 0x4A, unchecked(0xD3), unchecked(0xE6), 0x6B, 0x45, 0x7D, unchecked(0xE8), 0x4B, unchecked(0xD6), 0x32, unchecked(0xD8), unchecked(0xFD), 0x37, 0x71, unchecked(0xF1), unchecked(0xE1), 0x30, 0x0F, unchecked(0xF8), 0x1B, unchecked(0x87), unchecked(0xFA), 0x06, 0x3F, 0x5E, unchecked(0xBA), unchecked(0xAE), 0x5B, unchecked(0x8A), 0x00, unchecked(0xBC), unchecked(0x9D), 0x6D, unchecked(0xC1), unchecked(0xB1), 0x0E, unchecked(0x80), 0x5D, unchecked(0xD2), unchecked(0xD5), unchecked(0xA0), unchecked(0x84), 0x07, 0x14, unchecked(0xB5), unchecked(0x90), 0x2C, unchecked(0xA3), unchecked(0xB2), 0x73, 0x4C, 0x54, unchecked(0x92), 0x74, 0x36, 0x51, 0x38, unchecked(0xB0), unchecked(0xBD), 0x5A, unchecked(0xFC), 0x60, 0x62, unchecked(0x96), 0x6C, 0x42, unchecked(0xF7), 0x10, 0x7C, 0x28, 0x27, unchecked(0x8C), 0x13, unchecked(0x95), unchecked(0x9C), unchecked(0xC7), 0x24, 0x46, 0x3B, 0x70, unchecked(0xCA), unchecked(0xE3), unchecked(0x85), unchecked(0xCB), 0x11, unchecked(0xD0), unchecked(0x93), unchecked(0xB8), unchecked(0xA6), unchecked(0x83), 0x20, unchecked(0xFF), unchecked(0x9F), 0x77, unchecked(0xC3), unchecked(0xCC), 0x03, 0x6F, 0x08, unchecked(0xBF), 0x40, unchecked(0xE7), 0x2B, unchecked(0xE2), 0x79, 0x0C, unchecked(0xAA), unchecked(0x82), 0x41, 0x3A, unchecked(0xEA), unchecked(0xB9), unchecked(0xE4), unchecked(0x9A), unchecked(0xA4), unchecked(0x97), 0x7E, unchecked(0xDA), 0x7A, 0x17, 0x66, unchecked(0x94), unchecked(0xA1), 0x1D, 0x3D, unchecked(0xF0), unchecked(0xDE), unchecked(0xB3), 0x0B, 0x72, unchecked(0xA7), 0x1C, unchecked(0xEF), unchecked(0xD1), 0x53, 0x3E, unchecked(0x8F), 0x33, 0x26, 0x5F, unchecked(0xEC), 0x76, 0x2A, 0x49, unchecked(0x81), unchecked(0x88), unchecked(0xEE), 0x21, unchecked(0xC4), 0x1A, unchecked(0xEB), unchecked(0xD9), unchecked(0xC5), 0x39, unchecked(0x99), unchecked(0xCD), unchecked(0xAD), 0x31, unchecked(0x8B), 0x01, 0x18, 0x23, unchecked(0xDD), 0x1F, 0x4E, 0x2D, unchecked(0xF9), 0x48, 0x4F, unchecked(0xF2), 0x65, unchecked(0x8E), 0x78, 0x5C, 0x58, 0x19, unchecked(0x8D), unchecked(0xE5), unchecked(0x98), 0x57, 0x67, 0x7F, 0x05, 0x64, unchecked(0xAF), 0x63, unchecked(0xB6), unchecked(0xFE), unchecked(0xF5), unchecked(0xB7), 0x3C, unchecked(0xA5), unchecked(0xCE), unchecked(0xE9), 0x68, 0x44, unchecked(0xE0), 0x4D, 0x43, 0x69, 0x29, 0x2E, unchecked(0xAC), 0x15, 0x59, unchecked(0xA8), 0x0A, unchecked(0x9E), 0x6E, 0x47, unchecked(0xDF), 0x34, 0x35, 0x6A, unchecked(0xCF), unchecked(0xDC), 0x22, unchecked(0xC9), unchecked(0xC0), unchecked(0x9B), unchecked(0x89), unchecked(0xD4), unchecked(0xED), unchecked(0xAB), 0x12, unchecked(0xA2), 0x0D, 0x52, unchecked(0xBB), 0x02, 0x2F, unchecked(0xA9), unchecked(0xD7), 0x61, 0x1E, unchecked(0xB4), 0x50, 0x04, unchecked(0xF6), unchecked(0xC2), 0x16, 0x25, unchecked(0x86), 0x56, 0x55, 0x09, unchecked(0xBE), unchecked(0x91)}
		};

		/// <summary>
		/// Define the fixed p0/p1 permutations used in keyed S-box lookup.
		/// By changing the following constant definitions, the S-boxes will
		/// automatically get changed in the Twofish engine.
		/// </summary>
		private const int P_00 = 1;
		private const int P_01 = 0;
		private const int P_02 = 0;
		private static readonly int P_03 = P_01 ^ 1;
		private const int P_04 = 1;

		private const int P_10 = 0;
		private const int P_11 = 0;
		private const int P_12 = 1;
		private static readonly int P_13 = P_11 ^ 1;
		private const int P_14 = 0;

		private const int P_20 = 1;
		private const int P_21 = 1;
		private const int P_22 = 0;
		private static readonly int P_23 = P_21 ^ 1;
		private const int P_24 = 0;

		private const int P_30 = 0;
		private const int P_31 = 1;
		private const int P_32 = 1;
		private static readonly int P_33 = P_31 ^ 1;
		private const int P_34 = 1;

		/* Primitive polynomial for GF(256) */
		private const int GF256_FDBK = 0x169;
		private static readonly int GF256_FDBK_2 = GF256_FDBK / 2;
		private static readonly int GF256_FDBK_4 = GF256_FDBK / 4;

		private const int RS_GF_FDBK = 0x14D; // field generator

		//====================================
		// Useful constants
		//====================================

		private const int ROUNDS = 16;
		private const int MAX_ROUNDS = 16; // bytes = 128 bits
		private const int BLOCK_SIZE = 16; // bytes = 128 bits
		private const int MAX_KEY_BITS = 256;

		private const int INPUT_WHITEN = 0;
		private static readonly int OUTPUT_WHITEN = INPUT_WHITEN + BLOCK_SIZE / 4; // 4
		private static readonly int ROUND_SUBKEYS = OUTPUT_WHITEN + BLOCK_SIZE / 4; // 8

		private static readonly int TOTAL_SUBKEYS = ROUND_SUBKEYS + 2 * MAX_ROUNDS; // 40

		private const int SK_STEP = 0x02020202;
		private const int SK_BUMP = 0x01010101;
		private const int SK_ROTL = 9;

		private bool encrypting = false;

		private int[] gMDS0 = new int[MAX_KEY_BITS];
		private int[] gMDS1 = new int[MAX_KEY_BITS];
		private int[] gMDS2 = new int[MAX_KEY_BITS];
		private int[] gMDS3 = new int[MAX_KEY_BITS];

		/// <summary>
		/// gSubKeys[] and gSBox[] are eventually used in the 
		/// encryption and decryption methods.
		/// </summary>
		private int[] gSubKeys;
		private int[] gSBox;

		private int k64Cnt = 0;

		private byte[] workingKey = null;

		public TwofishEngine()
		{
			// calculate the MDS matrix
			int[] m1 = new int[2];
			int[] mX = new int[2];
			int[] mY = new int[2];
			int j;

			for (int i = 0; i < MAX_KEY_BITS ; i++)
			{
				j = P[0][i] & 0xff;
				m1[0] = j;
				mX[0] = Mx_X(j) & 0xff;
				mY[0] = Mx_Y(j) & 0xff;

				j = P[1][i] & 0xff;
				m1[1] = j;
				mX[1] = Mx_X(j) & 0xff;
				mY[1] = Mx_Y(j) & 0xff;

				gMDS0[i] = m1[P_00] | mX[P_00] << 8 | mY[P_00] << 16 | mY[P_00] << 24;

				gMDS1[i] = mY[P_10] | mY[P_10] << 8 | mX[P_10] << 16 | m1[P_10] << 24;

				gMDS2[i] = mX[P_20] | mY[P_20] << 8 | m1[P_20] << 16 | mY[P_20] << 24;

				gMDS3[i] = mX[P_30] | m1[P_30] << 8 | mY[P_30] << 16 | mX[P_30] << 24;
			}
		}

		/// <summary>
		/// initialise a Twofish cipher.
		/// </summary>
		/// <param name="encrypting"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public void init(bool encrypting, CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				this.encrypting = encrypting;
				this.workingKey = ((KeyParameter)@params).getKey();
				this.k64Cnt = (this.workingKey.Length / 8); // pre-padded ?
				setKey(this.workingKey);

				return;
			}

			throw new IllegalArgumentException("invalid parameter passed to Twofish init - " + @params.GetType().getName());
		}

		public string getAlgorithmName()
		{
			return "Twofish";
		}

		public int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("Twofish not initialised");
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

		public void reset()
		{
			if (this.workingKey != null)
			{
				setKey(this.workingKey);
			}
		}

		public int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		//==================================
		// Private Implementation
		//==================================

		private void setKey(byte[] key)
		{
			int[] k32e = new int[MAX_KEY_BITS / 64]; // 4
			int[] k32o = new int[MAX_KEY_BITS / 64]; // 4

			int[] sBoxKeys = new int[MAX_KEY_BITS / 64]; // 4
			gSubKeys = new int[TOTAL_SUBKEYS];

			if (k64Cnt < 1)
			{
				throw new IllegalArgumentException("Key size less than 64 bits");
			}

			if (k64Cnt > 4)
			{
				throw new IllegalArgumentException("Key size larger than 256 bits");
			}

			/*
			 * k64Cnt is the number of 8 byte blocks (64 chunks)
			 * that are in the input key.  The input key is a
			 * maximum of 32 bytes (256 bits), so the range
			 * for k64Cnt is 1..4
			 */
			for (int i = 0; i < k64Cnt ; i++)
			{
				int p = i * 8;

				k32e[i] = BytesTo32Bits(key, p);
				k32o[i] = BytesTo32Bits(key, p + 4);

				sBoxKeys[k64Cnt - 1 - i] = RS_MDS_Encode(k32e[i], k32o[i]);
			}

			int q, A, B;
			for (int i = 0; i < TOTAL_SUBKEYS / 2 ; i++)
			{
				q = i * SK_STEP;
				A = F32(q, k32e);
				B = F32(q + SK_BUMP, k32o);
				B = B << 8 | (int)((uint)B >> 24);
				A += B;
				gSubKeys[i * 2] = A;
				A += B;
				gSubKeys[i * 2 + 1] = A << SK_ROTL | (int)((uint)A >> (32 - SK_ROTL));
			}

			/*
			 * fully expand the table for speed
			 */
			int k0 = sBoxKeys[0];
			int k1 = sBoxKeys[1];
			int k2 = sBoxKeys[2];
			int k3 = sBoxKeys[3];
			int b0a, b1a, b2a, b3a;
			gSBox = new int[4 * MAX_KEY_BITS];
			for (int i = 0; i < MAX_KEY_BITS; i++)
			{
				b0a = b1a = b2a = b3a = i;
				switch (k64Cnt & 3)
				{
					case 1:
						gSBox[i * 2] = gMDS0[(P[P_01][b0a] & 0xff) ^ b0(k0)];
						gSBox[i * 2 + 1] = gMDS1[(P[P_11][b1a] & 0xff) ^ b1(k0)];
						gSBox[i * 2 + 0x200] = gMDS2[(P[P_21][b2a] & 0xff) ^ b2(k0)];
						gSBox[i * 2 + 0x201] = gMDS3[(P[P_31][b3a] & 0xff) ^ b3(k0)];
					break;
					case 0: // 256 bits of key
						b0a = (P[P_04][b0a] & 0xff) ^ b0(k3);
						b1a = (P[P_14][b1a] & 0xff) ^ b1(k3);
						b2a = (P[P_24][b2a] & 0xff) ^ b2(k3);
						b3a = (P[P_34][b3a] & 0xff) ^ b3(k3);
						// fall through, having pre-processed b[0]..b[3] with k32[3]
						goto case 3;
					case 3: // 192 bits of key
						b0a = (P[P_03][b0a] & 0xff) ^ b0(k2);
						b1a = (P[P_13][b1a] & 0xff) ^ b1(k2);
						b2a = (P[P_23][b2a] & 0xff) ^ b2(k2);
						b3a = (P[P_33][b3a] & 0xff) ^ b3(k2);
						// fall through, having pre-processed b[0]..b[3] with k32[2]
						goto case 2;
					case 2: // 128 bits of key
						gSBox[i * 2] = gMDS0[(P[P_01][(P[P_02][b0a] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)];
						gSBox[i * 2 + 1] = gMDS1[(P[P_11][(P[P_12][b1a] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)];
						gSBox[i * 2 + 0x200] = gMDS2[(P[P_21][(P[P_22][b2a] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)];
						gSBox[i * 2 + 0x201] = gMDS3[(P[P_31][(P[P_32][b3a] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
					break;
				}
			}

			/* 
			 * the function exits having setup the gSBox with the 
			 * input key material.
			 */
		}

		/// <summary>
		/// Encrypt the given input starting at the given offset and place
		/// the result in the provided buffer starting at the given offset.
		/// The input will be an exact multiple of our blocksize.
		/// 
		/// encryptBlock uses the pre-calculated gSBox[] and subKey[]
		/// arrays.
		/// </summary>
		private void encryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex)
		{
			int x0 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[INPUT_WHITEN];
			int x1 = BytesTo32Bits(src, srcIndex + 4) ^ gSubKeys[INPUT_WHITEN + 1];
			int x2 = BytesTo32Bits(src, srcIndex + 8) ^ gSubKeys[INPUT_WHITEN + 2];
			int x3 = BytesTo32Bits(src, srcIndex + 12) ^ gSubKeys[INPUT_WHITEN + 3];

			int k = ROUND_SUBKEYS;
			int t0, t1;
			for (int r = 0; r < ROUNDS; r += 2)
			{
				t0 = Fe32_0(x0);
				t1 = Fe32_3(x1);
				x2 ^= t0 + t1 + gSubKeys[k++];
				x2 = (int)((uint)x2 >> 1) | x2 << 31;
				x3 = (x3 << 1 | (int)((uint)x3 >> 31)) ^ (t0 + 2 * t1 + gSubKeys[k++]);

				t0 = Fe32_0(x2);
				t1 = Fe32_3(x3);
				x0 ^= t0 + t1 + gSubKeys[k++];
				x0 = (int)((uint)x0 >> 1) | x0 << 31;
				x1 = (x1 << 1 | (int)((uint)x1 >> 31)) ^ (t0 + 2 * t1 + gSubKeys[k++]);
			}

			Bits32ToBytes(x2 ^ gSubKeys[OUTPUT_WHITEN], dst, dstIndex);
			Bits32ToBytes(x3 ^ gSubKeys[OUTPUT_WHITEN + 1], dst, dstIndex + 4);
			Bits32ToBytes(x0 ^ gSubKeys[OUTPUT_WHITEN + 2], dst, dstIndex + 8);
			Bits32ToBytes(x1 ^ gSubKeys[OUTPUT_WHITEN + 3], dst, dstIndex + 12);
		}

		/// <summary>
		/// Decrypt the given input starting at the given offset and place
		/// the result in the provided buffer starting at the given offset.
		/// The input will be an exact multiple of our blocksize.
		/// </summary>
		private void decryptBlock(byte[] src, int srcIndex, byte[] dst, int dstIndex)
		{
			int x2 = BytesTo32Bits(src, srcIndex) ^ gSubKeys[OUTPUT_WHITEN];
			int x3 = BytesTo32Bits(src, srcIndex + 4) ^ gSubKeys[OUTPUT_WHITEN + 1];
			int x0 = BytesTo32Bits(src, srcIndex + 8) ^ gSubKeys[OUTPUT_WHITEN + 2];
			int x1 = BytesTo32Bits(src, srcIndex + 12) ^ gSubKeys[OUTPUT_WHITEN + 3];

			int k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
			int t0, t1;
			for (int r = 0; r < ROUNDS ; r += 2)
			{
				t0 = Fe32_0(x2);
				t1 = Fe32_3(x3);
				x1 ^= t0 + 2 * t1 + gSubKeys[k--];
				x0 = (x0 << 1 | (int)((uint)x0 >> 31)) ^ (t0 + t1 + gSubKeys[k--]);
				x1 = (int)((uint)x1 >> 1) | x1 << 31;

				t0 = Fe32_0(x0);
				t1 = Fe32_3(x1);
				x3 ^= t0 + 2 * t1 + gSubKeys[k--];
				x2 = (x2 << 1 | (int)((uint)x2 >> 31)) ^ (t0 + t1 + gSubKeys[k--]);
				x3 = (int)((uint)x3 >> 1) | x3 << 31;
			}

			Bits32ToBytes(x0 ^ gSubKeys[INPUT_WHITEN], dst, dstIndex);
			Bits32ToBytes(x1 ^ gSubKeys[INPUT_WHITEN + 1], dst, dstIndex + 4);
			Bits32ToBytes(x2 ^ gSubKeys[INPUT_WHITEN + 2], dst, dstIndex + 8);
			Bits32ToBytes(x3 ^ gSubKeys[INPUT_WHITEN + 3], dst, dstIndex + 12);
		}

		/* 
		 * TODO:  This can be optimised and made cleaner by combining
		 * the functionality in this function and applying it appropriately
		 * to the creation of the subkeys during key setup.
		 */
		private int F32(int x, int[] k32)
		{
			int b0a = b0(x);
			int b1a = b1(x);
			int b2a = b2(x);
			int b3a = b3(x);
			int k0 = k32[0];
			int k1 = k32[1];
			int k2 = k32[2];
			int k3 = k32[3];

			int result = 0;
			switch (k64Cnt & 3)
			{
				case 1:
					result = gMDS0[(P[P_01][b0a] & 0xff) ^ b0(k0)] ^ gMDS1[(P[P_11][b1a] & 0xff) ^ b1(k0)] ^ gMDS2[(P[P_21][b2a] & 0xff) ^ b2(k0)] ^ gMDS3[(P[P_31][b3a] & 0xff) ^ b3(k0)];
					break;
				case 0: // 256 bits of key
					b0a = (P[P_04][b0a] & 0xff) ^ b0(k3);
					b1a = (P[P_14][b1a] & 0xff) ^ b1(k3);
					b2a = (P[P_24][b2a] & 0xff) ^ b2(k3);
					b3a = (P[P_34][b3a] & 0xff) ^ b3(k3);
					goto case 3;
				case 3:
					b0a = (P[P_03][b0a] & 0xff) ^ b0(k2);
					b1a = (P[P_13][b1a] & 0xff) ^ b1(k2);
					b2a = (P[P_23][b2a] & 0xff) ^ b2(k2);
					b3a = (P[P_33][b3a] & 0xff) ^ b3(k2);
					goto case 2;
				case 2:
					result = gMDS0[(P[P_01][(P[P_02][b0a] & 0xff) ^ b0(k1)] & 0xff) ^ b0(k0)] ^ gMDS1[(P[P_11][(P[P_12][b1a] & 0xff) ^ b1(k1)] & 0xff) ^ b1(k0)] ^ gMDS2[(P[P_21][(P[P_22][b2a] & 0xff) ^ b2(k1)] & 0xff) ^ b2(k0)] ^ gMDS3[(P[P_31][(P[P_32][b3a] & 0xff) ^ b3(k1)] & 0xff) ^ b3(k0)];
				break;
			}
			return result;
		}

		/// <summary>
		/// Use (12, 8) Reed-Solomon code over GF(256) to produce
		/// a key S-box 32-bit entity from 2 key material 32-bit
		/// entities.
		/// </summary>
		/// <param name="k0"> first 32-bit entity </param>
		/// <param name="k1"> second 32-bit entity </param>
		/// <returns>     Remainder polynomial generated using RS code </returns>
		private int RS_MDS_Encode(int k0, int k1)
		{
			int r = k1;
			for (int i = 0 ; i < 4 ; i++) // shift 1 byte at a time
			{
				r = RS_rem(r);
			}
			r ^= k0;
			for (int i = 0 ; i < 4 ; i++)
			{
				r = RS_rem(r);
			}

			return r;
		}

		/// <summary>
		/// Reed-Solomon code parameters: (12,8) reversible code:<para>
		/// <pre>
		/// g(x) = x^4 + (a+1/a)x^3 + ax^2 + (a+1/a)x + 1
		/// </pre>
		/// where a = primitive root of field generator 0x14D
		/// </para>
		/// </summary>
		private int RS_rem(int x)
		{
			int b = ((int)((uint)x >> 24)) & 0xff;
			int g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xff;
			int g3 = (((int)((uint)b >> 1)) ^ ((b & 0x01) != 0 ? ((int)((uint)RS_GF_FDBK >> 1)) : 0)) ^ g2;
			return ((x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
		}

		private int LFSR1(int x)
		{
			return (x >> 1) ^ (((x & 0x01) != 0) ? GF256_FDBK_2 : 0);
		}

		private int LFSR2(int x)
		{
			return (x >> 2) ^ (((x & 0x02) != 0) ? GF256_FDBK_2 : 0) ^ (((x & 0x01) != 0) ? GF256_FDBK_4 : 0);
		}

		private int Mx_X(int x)
		{
			return x ^ LFSR2(x);
		} // 5B

		private int Mx_Y(int x)
		{
			return x ^ LFSR1(x) ^ LFSR2(x);
		} // EF

		private int b0(int x)
		{
			return x & 0xff;
		}

		private int b1(int x)
		{
			return ((int)((uint)x >> 8)) & 0xff;
		}

		private int b2(int x)
		{
			return ((int)((uint)x >> 16)) & 0xff;
		}

		private int b3(int x)
		{
			return ((int)((uint)x >> 24)) & 0xff;
		}

		private int Fe32_0(int x)
		{
			return gSBox[0x000 + 2 * (x & 0xff)] ^ gSBox[0x001 + 2 * (((int)((uint)x >> 8)) & 0xff)] ^ gSBox[0x200 + 2 * (((int)((uint)x >> 16)) & 0xff)] ^ gSBox[0x201 + 2 * (((int)((uint)x >> 24)) & 0xff)];
		}

		private int Fe32_3(int x)
		{
			return gSBox[0x000 + 2 * (((int)((uint)x >> 24)) & 0xff)] ^ gSBox[0x001 + 2 * (x & 0xff)] ^ gSBox[0x200 + 2 * (((int)((uint)x >> 8)) & 0xff)] ^ gSBox[0x201 + 2 * (((int)((uint)x >> 16)) & 0xff)];
		}

		private int BytesTo32Bits(byte[] b, int p)
		{
			return ((b[p] & 0xff)) | ((b[p + 1] & 0xff) << 8) | ((b[p + 2] & 0xff) << 16) | ((b[p + 3] & 0xff) << 24);
		}

		private void Bits32ToBytes(int @in, byte[] b, int offset)
		{
			b[offset] = (byte)@in;
			b[offset + 1] = (byte)(@in >> 8);
			b[offset + 2] = (byte)(@in >> 16);
			b[offset + 3] = (byte)(@in >> 24);
		}
	}

}