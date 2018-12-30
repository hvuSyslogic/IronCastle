using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.digests
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// General Information
	/// <p/>
	/// 1. GOST R 34.11-2012 was developed by the Center for Information
	/// Protection and Special Communications of the Federal Security
	/// Service of the Russian Federation with participation of the Open
	/// joint-stock company "Information Technologies and Communication
	/// Systems" (InfoTeCS JSC).
	/// <p/>
	/// 2. GOST R 34.11-2012 was approved and introduced by Decree #216 of
	/// the Federal Agency on Technical Regulating and Metrology on
	/// 07.08.2012.
	/// <p/>
	/// 3. GOST R 34.11-2012 intended to replace GOST R 34.11-94 national
	/// standard of Russian Federation.
	/// <p/>
	/// Reference Implementation and Description can be found at: https://www.streebog.net/
	/// RFC: https://tools.ietf.org/html/rfc6986
	/// </summary>

	/// <summary>
	/// Base class for GOST3411-2012 256-bit and GOST3411-2012 512-bit digests.
	/// </summary>
	public abstract class GOST3411_2012Digest : ExtendedDigest, Memoable
	{
		private readonly byte[] IV = new byte[64];
		private readonly byte[] N = new byte[64];
		private readonly byte[] Sigma = new byte[64];
		private readonly byte[] Ki = new byte[64];
		private readonly byte[] m = new byte[64];
		private readonly byte[] h = new byte[64];

		// Temporary buffers
		private readonly byte[] tmp = new byte[64];
		private readonly byte[] block = new byte[64];

		private int bOff = 64;

		public GOST3411_2012Digest(byte[] IV)
		{
			JavaSystem.arraycopy(IV, 0, this.IV, 0, 64);
			JavaSystem.arraycopy(IV, 0, h, 0, 64);
		}

		public virtual int getByteLength()
		{
			return 64;
		}

		public abstract string getAlgorithmName();

		public abstract int getDigestSize();

		public virtual void update(byte @in)
		{
			block[--bOff] = @in;
			if (bOff == 0)
			{
				g_N(h, N, block);
				addMod512(N, 512);
				addMod512(Sigma, block);
				bOff = 64;
			}
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			while (bOff != 64 && len > 0)
			{
				update(@in[inOff++]);
				len--;
			}
			while (len >= 64)
			{
				JavaSystem.arraycopy(@in, inOff, tmp, 0, 64);
				reverse(tmp, block);
				g_N(h, N, block);
				addMod512(N, 512);
				addMod512(Sigma, block);

				len -= 64;
				inOff += 64;
			}
			while (len > 0)
			{
				update(@in[inOff++]);
				len--;
			}
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int lenM = 64 - bOff;

			// At this point it is certain that lenM is smaller than 64
			for (int i = 0; i != 64 - lenM; i++)
			{
				m[i] = 0;
			}

			m[63 - lenM] = 1;

			if (bOff != 64)
			{
				JavaSystem.arraycopy(block, bOff, m, 64 - lenM, lenM);
			}

			g_N(h, N, m);
			addMod512(N, lenM * 8);
			addMod512(Sigma, m);
			g_N(h, Zero, N);
			g_N(h, Zero, Sigma);

			reverse(h, tmp);
			JavaSystem.arraycopy(tmp, 0, @out, outOff, 64);

			reset();
			return 64;
		}

		public virtual void reset()
		{
			bOff = 64;
			Arrays.fill(N, (byte)0);
			Arrays.fill(Sigma, (byte)0);
			JavaSystem.arraycopy(IV, 0, h, 0, 64);
			Arrays.fill(block, (byte)0);
		}

		public abstract Memoable copy();

		public virtual void reset(Memoable other)
		{
			GOST3411_2012Digest o = (GOST3411_2012Digest)other;

			JavaSystem.arraycopy(o.IV, 0, this.IV, 0, 64);
			JavaSystem.arraycopy(o.N, 0, this.N, 0, 64);
			JavaSystem.arraycopy(o.Sigma, 0, this.Sigma, 0, 64);
			JavaSystem.arraycopy(o.Ki, 0, this.Ki, 0, 64);
			JavaSystem.arraycopy(o.m, 0, this.m, 0, 64);
			JavaSystem.arraycopy(o.h, 0, this.h, 0, 64);

			JavaSystem.arraycopy(o.block, 0, this.block, 0, 64);
			this.bOff = o.bOff;
		}

		private void F(byte[] V)
		{
			long[] res = new long[8];
			long r;

			r = 0;
			r ^= T[0][(V[56] & 0xFF)];
			r ^= T[1][(V[48] & 0xFF)];
			r ^= T[2][(V[40] & 0xFF)];
			r ^= T[3][(V[32] & 0xFF)];
			r ^= T[4][(V[24] & 0xFF)];
			r ^= T[5][(V[16] & 0xFF)];
			r ^= T[6][(V[8] & 0xFF)];
			r ^= T[7][(V[0] & 0xFF)];
			res[0] = r;

			r = 0;
			r ^= T[0][(V[57] & 0xFF)];
			r ^= T[1][(V[49] & 0xFF)];
			r ^= T[2][(V[41] & 0xFF)];
			r ^= T[3][(V[33] & 0xFF)];
			r ^= T[4][(V[25] & 0xFF)];
			r ^= T[5][(V[17] & 0xFF)];
			r ^= T[6][(V[9] & 0xFF)];
			r ^= T[7][(V[1] & 0xFF)];
			res[1] = r;

			r = 0;
			r ^= T[0][(V[58] & 0xFF)];
			r ^= T[1][(V[50] & 0xFF)];
			r ^= T[2][(V[42] & 0xFF)];
			r ^= T[3][(V[34] & 0xFF)];
			r ^= T[4][(V[26] & 0xFF)];
			r ^= T[5][(V[18] & 0xFF)];
			r ^= T[6][(V[10] & 0xFF)];
			r ^= T[7][(V[2] & 0xFF)];
			res[2] = r;

			r = 0;
			r ^= T[0][(V[59] & 0xFF)];
			r ^= T[1][(V[51] & 0xFF)];
			r ^= T[2][(V[43] & 0xFF)];
			r ^= T[3][(V[35] & 0xFF)];
			r ^= T[4][(V[27] & 0xFF)];
			r ^= T[5][(V[19] & 0xFF)];
			r ^= T[6][(V[11] & 0xFF)];
			r ^= T[7][(V[3] & 0xFF)];
			res[3] = r;

			r = 0;
			r ^= T[0][(V[60] & 0xFF)];
			r ^= T[1][(V[52] & 0xFF)];
			r ^= T[2][(V[44] & 0xFF)];
			r ^= T[3][(V[36] & 0xFF)];
			r ^= T[4][(V[28] & 0xFF)];
			r ^= T[5][(V[20] & 0xFF)];
			r ^= T[6][(V[12] & 0xFF)];
			r ^= T[7][(V[4] & 0xFF)];
			res[4] = r;

			r = 0;
			r ^= T[0][(V[61] & 0xFF)];
			r ^= T[1][(V[53] & 0xFF)];
			r ^= T[2][(V[45] & 0xFF)];
			r ^= T[3][(V[37] & 0xFF)];
			r ^= T[4][(V[29] & 0xFF)];
			r ^= T[5][(V[21] & 0xFF)];
			r ^= T[6][(V[13] & 0xFF)];
			r ^= T[7][(V[5] & 0xFF)];
			res[5] = r;

			r = 0;
			r ^= T[0][(V[62] & 0xFF)];
			r ^= T[1][(V[54] & 0xFF)];
			r ^= T[2][(V[46] & 0xFF)];
			r ^= T[3][(V[38] & 0xFF)];
			r ^= T[4][(V[30] & 0xFF)];
			r ^= T[5][(V[22] & 0xFF)];
			r ^= T[6][(V[14] & 0xFF)];
			r ^= T[7][(V[6] & 0xFF)];
			res[6] = r;

			r = 0;
			r ^= T[0][(V[63] & 0xFF)];
			r ^= T[1][(V[55] & 0xFF)];
			r ^= T[2][(V[47] & 0xFF)];
			r ^= T[3][(V[39] & 0xFF)];
			r ^= T[4][(V[31] & 0xFF)];
			r ^= T[5][(V[23] & 0xFF)];
			r ^= T[6][(V[15] & 0xFF)];
			r ^= T[7][(V[7] & 0xFF)];
			res[7] = r;

			r = res[0];
			V[7] = (byte)(r >> 56);
			V[6] = (byte)(r >> 48);
			V[5] = (byte)(r >> 40);
			V[4] = (byte)(r >> 32);
			V[3] = (byte)(r >> 24);
			V[2] = (byte)(r >> 16);
			V[1] = (byte)(r >> 8);
			V[0] = (byte)(r);

			r = res[1];
			V[15] = (byte)(r >> 56);
			V[14] = (byte)(r >> 48);
			V[13] = (byte)(r >> 40);
			V[12] = (byte)(r >> 32);
			V[11] = (byte)(r >> 24);
			V[10] = (byte)(r >> 16);
			V[9] = (byte)(r >> 8);
			V[8] = (byte)(r);

			r = res[2];
			V[23] = (byte)(r >> 56);
			V[22] = (byte)(r >> 48);
			V[21] = (byte)(r >> 40);
			V[20] = (byte)(r >> 32);
			V[19] = (byte)(r >> 24);
			V[18] = (byte)(r >> 16);
			V[17] = (byte)(r >> 8);
			V[16] = (byte)(r);

			r = res[3];
			V[31] = (byte)(r >> 56);
			V[30] = (byte)(r >> 48);
			V[29] = (byte)(r >> 40);
			V[28] = (byte)(r >> 32);
			V[27] = (byte)(r >> 24);
			V[26] = (byte)(r >> 16);
			V[25] = (byte)(r >> 8);
			V[24] = (byte)(r);

			r = res[4];
			V[39] = (byte)(r >> 56);
			V[38] = (byte)(r >> 48);
			V[37] = (byte)(r >> 40);
			V[36] = (byte)(r >> 32);
			V[35] = (byte)(r >> 24);
			V[34] = (byte)(r >> 16);
			V[33] = (byte)(r >> 8);
			V[32] = (byte)(r);

			r = res[5];
			V[47] = (byte)(r >> 56);
			V[46] = (byte)(r >> 48);
			V[45] = (byte)(r >> 40);
			V[44] = (byte)(r >> 32);
			V[43] = (byte)(r >> 24);
			V[42] = (byte)(r >> 16);
			V[41] = (byte)(r >> 8);
			V[40] = (byte)(r);

			r = res[6];
			V[55] = (byte)(r >> 56);
			V[54] = (byte)(r >> 48);
			V[53] = (byte)(r >> 40);
			V[52] = (byte)(r >> 32);
			V[51] = (byte)(r >> 24);
			V[50] = (byte)(r >> 16);
			V[49] = (byte)(r >> 8);
			V[48] = (byte)(r);

			r = res[7];
			V[63] = (byte)(r >> 56);
			V[62] = (byte)(r >> 48);
			V[61] = (byte)(r >> 40);
			V[60] = (byte)(r >> 32);
			V[59] = (byte)(r >> 24);
			V[58] = (byte)(r >> 16);
			V[57] = (byte)(r >> 8);
			V[56] = (byte)(r);
		}

		private void xor512(byte[] A, byte[] B)
		{
			for (int i = 0; i < 64; ++i)
			{
				A[i] ^= B[i];
			}
		}

		private void E(byte[] K, byte[] m)
		{
			JavaSystem.arraycopy(K, 0, Ki, 0, 64);
			xor512(K, m);
			F(K);
			for (int i = 0; i < 11; ++i)
			{
				xor512(Ki, C[i]);
				F(Ki);
				xor512(K, Ki);
				F(K);
			}
			xor512(Ki, C[11]);
			F(Ki);
			xor512(K, Ki);
		}

		private void g_N(byte[] h, byte[] N, byte[] m)
		{
			JavaSystem.arraycopy(h, 0, tmp, 0, 64);

			xor512(h, N);
			F(h);

			E(h, m);
			xor512(h, tmp);
			xor512(h, m);
		}

		private void addMod512(byte[] A, int num)
		{
			int c;
			c = (A[63] & 0xFF) + (num & 0xFF);
			A[63] = (byte)c;

			c = (A[62] & 0xFF) + ((num >> 8) & 0xFF) + (c >> 8);
			A[62] = (byte)c;

			for (int i = 61; (i >= 0) && (c > 0); --i)
			{
				c = (A[i] & 0xFF) + (c >> 8);
				A[i] = (byte)c;
			}
		}

		private void addMod512(byte[] A, byte[] B)
		{
			for (int c = 0, i = 63; i >= 0; --i)
			{
				c = (A[i] & 0xFF) + (B[i] & 0xFF) + (c >> 8);
				A[i] = (byte)c;
			}
		}

		private void reverse(byte[] src, byte[] dst)
		{

			int len = src.Length;
			for (int i = 0; i < len; i++)
			{
				dst[len - 1 - i] = src[i];
			}
		}

		private static readonly byte[][] C = new byte[][]
		{
			new byte[] {unchecked((byte)0xb1), (byte)0x08, (byte)0x5b, unchecked((byte)0xda), (byte)0x1e, unchecked((byte)0xca), unchecked((byte)0xda), unchecked((byte)0xe9), unchecked((byte)0xeb), unchecked((byte)0xcb), (byte)0x2f, unchecked((byte)0x81), unchecked((byte)0xc0), (byte)0x65, (byte)0x7c, (byte)0x1f, (byte)0x2f, (byte)0x6a, (byte)0x76, (byte)0x43, (byte)0x2e, (byte)0x45, unchecked((byte)0xd0), (byte)0x16, (byte)0x71, (byte)0x4e, unchecked((byte)0xb8), unchecked((byte)0x8d), (byte)0x75, unchecked((byte)0x85), unchecked((byte)0xc4), unchecked((byte)0xfc), (byte)0x4b, (byte)0x7c, unchecked((byte)0xe0), unchecked((byte)0x91), unchecked((byte)0x92), (byte)0x67, (byte)0x69, (byte)0x01, unchecked((byte)0xa2), (byte)0x42, (byte)0x2a, (byte)0x08, unchecked((byte)0xa4), (byte)0x60, unchecked((byte)0xd3), (byte)0x15, (byte)0x05, (byte)0x76, (byte)0x74, (byte)0x36, unchecked((byte)0xcc), (byte)0x74, (byte)0x4d, (byte)0x23, unchecked((byte)0xdd), unchecked((byte)0x80), (byte)0x65, (byte)0x59, unchecked((byte)0xf2), unchecked((byte)0xa6), (byte)0x45, (byte)0x07},
			new byte[] {(byte)0x6f, unchecked((byte)0xa3), unchecked((byte)0xb5), unchecked((byte)0x8a), unchecked((byte)0xa9), unchecked((byte)0x9d), (byte)0x2f, (byte)0x1a, (byte)0x4f, unchecked((byte)0xe3), unchecked((byte)0x9d), (byte)0x46, (byte)0x0f, (byte)0x70, unchecked((byte)0xb5), unchecked((byte)0xd7), unchecked((byte)0xf3), unchecked((byte)0xfe), unchecked((byte)0xea), (byte)0x72, (byte)0x0a, (byte)0x23, (byte)0x2b, unchecked((byte)0x98), (byte)0x61, unchecked((byte)0xd5), (byte)0x5e, (byte)0x0f, (byte)0x16, unchecked((byte)0xb5), (byte)0x01, (byte)0x31, unchecked((byte)0x9a), unchecked((byte)0xb5), (byte)0x17, (byte)0x6b, (byte)0x12, unchecked((byte)0xd6), unchecked((byte)0x99), (byte)0x58, (byte)0x5c, unchecked((byte)0xb5), (byte)0x61, unchecked((byte)0xc2), unchecked((byte)0xdb), (byte)0x0a, unchecked((byte)0xa7), unchecked((byte)0xca), (byte)0x55, unchecked((byte)0xdd), unchecked((byte)0xa2), (byte)0x1b, unchecked((byte)0xd7), unchecked((byte)0xcb), unchecked((byte)0xcd), (byte)0x56, unchecked((byte)0xe6), (byte)0x79, (byte)0x04, (byte)0x70, (byte)0x21, unchecked((byte)0xb1), unchecked((byte)0x9b), unchecked((byte)0xb7)},
			new byte[] {unchecked((byte)0xf5), (byte)0x74, unchecked((byte)0xdc), unchecked((byte)0xac), (byte)0x2b, unchecked((byte)0xce), (byte)0x2f, unchecked((byte)0xc7), (byte)0x0a, (byte)0x39, unchecked((byte)0xfc), (byte)0x28, (byte)0x6a, (byte)0x3d, unchecked((byte)0x84), (byte)0x35, (byte)0x06, unchecked((byte)0xf1), (byte)0x5e, (byte)0x5f, (byte)0x52, unchecked((byte)0x9c), (byte)0x1f, unchecked((byte)0x8b), unchecked((byte)0xf2), unchecked((byte)0xea), (byte)0x75, (byte)0x14, unchecked((byte)0xb1), (byte)0x29, (byte)0x7b, (byte)0x7b, unchecked((byte)0xd3), unchecked((byte)0xe2), (byte)0x0f, unchecked((byte)0xe4), unchecked((byte)0x90), (byte)0x35, unchecked((byte)0x9e), unchecked((byte)0xb1), unchecked((byte)0xc1), unchecked((byte)0xc9), (byte)0x3a, (byte)0x37, (byte)0x60, (byte)0x62, unchecked((byte)0xdb), (byte)0x09, unchecked((byte)0xc2), unchecked((byte)0xb6), unchecked((byte)0xf4), (byte)0x43, unchecked((byte)0x86), (byte)0x7a, unchecked((byte)0xdb), (byte)0x31, unchecked((byte)0x99), (byte)0x1e, unchecked((byte)0x96), unchecked((byte)0xf5), (byte)0x0a, unchecked((byte)0xba), (byte)0x0a, unchecked((byte)0xb2)},
			new byte[] {unchecked((byte)0xef), (byte)0x1f, unchecked((byte)0xdf), unchecked((byte)0xb3), unchecked((byte)0xe8), (byte)0x15, (byte)0x66, unchecked((byte)0xd2), unchecked((byte)0xf9), (byte)0x48, unchecked((byte)0xe1), unchecked((byte)0xa0), (byte)0x5d, (byte)0x71, unchecked((byte)0xe4), unchecked((byte)0xdd), (byte)0x48, unchecked((byte)0x8e), unchecked((byte)0x85), (byte)0x7e, (byte)0x33, (byte)0x5c, (byte)0x3c, (byte)0x7d, unchecked((byte)0x9d), (byte)0x72, (byte)0x1c, unchecked((byte)0xad), (byte)0x68, (byte)0x5e, (byte)0x35, (byte)0x3f, unchecked((byte)0xa9), unchecked((byte)0xd7), (byte)0x2c, unchecked((byte)0x82), unchecked((byte)0xed), (byte)0x03, unchecked((byte)0xd6), (byte)0x75, unchecked((byte)0xd8), unchecked((byte)0xb7), (byte)0x13, (byte)0x33, unchecked((byte)0x93), (byte)0x52, (byte)0x03, unchecked((byte)0xbe), (byte)0x34, (byte)0x53, unchecked((byte)0xea), unchecked((byte)0xa1), unchecked((byte)0x93), unchecked((byte)0xe8), (byte)0x37, unchecked((byte)0xf1), (byte)0x22, (byte)0x0c, unchecked((byte)0xbe), unchecked((byte)0xbc), unchecked((byte)0x84), unchecked((byte)0xe3), unchecked((byte)0xd1), (byte)0x2e},
			new byte[] {(byte)0x4b, unchecked((byte)0xea), (byte)0x6b, unchecked((byte)0xac), unchecked((byte)0xad), (byte)0x47, (byte)0x47, unchecked((byte)0x99), unchecked((byte)0x9a), (byte)0x3f, (byte)0x41, (byte)0x0c, (byte)0x6c, unchecked((byte)0xa9), (byte)0x23, (byte)0x63, (byte)0x7f, (byte)0x15, (byte)0x1c, (byte)0x1f, (byte)0x16, unchecked((byte)0x86), (byte)0x10, (byte)0x4a, (byte)0x35, unchecked((byte)0x9e), (byte)0x35, unchecked((byte)0xd7), unchecked((byte)0x80), (byte)0x0f, unchecked((byte)0xff), unchecked((byte)0xbd), unchecked((byte)0xbf), unchecked((byte)0xcd), (byte)0x17, (byte)0x47, (byte)0x25, (byte)0x3a, unchecked((byte)0xf5), unchecked((byte)0xa3), unchecked((byte)0xdf), unchecked((byte)0xff), (byte)0x00, unchecked((byte)0xb7), (byte)0x23, (byte)0x27, (byte)0x1a, (byte)0x16, (byte)0x7a, (byte)0x56, unchecked((byte)0xa2), (byte)0x7e, unchecked((byte)0xa9), unchecked((byte)0xea), (byte)0x63, unchecked((byte)0xf5), (byte)0x60, (byte)0x17, (byte)0x58, unchecked((byte)0xfd), (byte)0x7c, (byte)0x6c, unchecked((byte)0xfe), (byte)0x57},
			new byte[] {unchecked((byte)0xae), (byte)0x4f, unchecked((byte)0xae), unchecked((byte)0xae), (byte)0x1d, (byte)0x3a, unchecked((byte)0xd3), unchecked((byte)0xd9), (byte)0x6f, unchecked((byte)0xa4), unchecked((byte)0xc3), (byte)0x3b, (byte)0x7a, (byte)0x30, (byte)0x39, unchecked((byte)0xc0), (byte)0x2d, (byte)0x66, unchecked((byte)0xc4), unchecked((byte)0xf9), (byte)0x51, (byte)0x42, unchecked((byte)0xa4), (byte)0x6c, (byte)0x18, (byte)0x7f, unchecked((byte)0x9a), unchecked((byte)0xb4), unchecked((byte)0x9a), unchecked((byte)0xf0), unchecked((byte)0x8e), unchecked((byte)0xc6), unchecked((byte)0xcf), unchecked((byte)0xfa), unchecked((byte)0xa6), unchecked((byte)0xb7), (byte)0x1c, unchecked((byte)0x9a), unchecked((byte)0xb7), unchecked((byte)0xb4), (byte)0x0a, unchecked((byte)0xf2), (byte)0x1f, (byte)0x66, unchecked((byte)0xc2), unchecked((byte)0xbe), unchecked((byte)0xc6), unchecked((byte)0xb6), unchecked((byte)0xbf), (byte)0x71, unchecked((byte)0xc5), (byte)0x72, (byte)0x36, unchecked((byte)0x90), (byte)0x4f, (byte)0x35, unchecked((byte)0xfa), (byte)0x68, (byte)0x40, (byte)0x7a, (byte)0x46, (byte)0x64, (byte)0x7d, (byte)0x6e},
			new byte[] {unchecked((byte)0xf4), unchecked((byte)0xc7), (byte)0x0e, (byte)0x16, unchecked((byte)0xee), unchecked((byte)0xaa), unchecked((byte)0xc5), unchecked((byte)0xec), (byte)0x51, unchecked((byte)0xac), unchecked((byte)0x86), unchecked((byte)0xfe), unchecked((byte)0xbf), (byte)0x24, (byte)0x09, (byte)0x54, (byte)0x39, unchecked((byte)0x9e), unchecked((byte)0xc6), unchecked((byte)0xc7), unchecked((byte)0xe6), unchecked((byte)0xbf), unchecked((byte)0x87), unchecked((byte)0xc9), unchecked((byte)0xd3), (byte)0x47, (byte)0x3e, (byte)0x33, (byte)0x19, (byte)0x7a, unchecked((byte)0x93), unchecked((byte)0xc9), (byte)0x09, unchecked((byte)0x92), unchecked((byte)0xab), unchecked((byte)0xc5), (byte)0x2d, unchecked((byte)0x82), (byte)0x2c, (byte)0x37, (byte)0x06, (byte)0x47, (byte)0x69, unchecked((byte)0x83), (byte)0x28, (byte)0x4a, (byte)0x05, (byte)0x04, (byte)0x35, (byte)0x17, (byte)0x45, (byte)0x4c, unchecked((byte)0xa2), (byte)0x3c, (byte)0x4a, unchecked((byte)0xf3), unchecked((byte)0x88), unchecked((byte)0x86), (byte)0x56, (byte)0x4d, (byte)0x3a, (byte)0x14, unchecked((byte)0xd4), unchecked((byte)0x93)},
			new byte[] {unchecked((byte)0x9b), (byte)0x1f, (byte)0x5b, (byte)0x42, (byte)0x4d, unchecked((byte)0x93), unchecked((byte)0xc9), unchecked((byte)0xa7), (byte)0x03, unchecked((byte)0xe7), unchecked((byte)0xaa), (byte)0x02, (byte)0x0c, (byte)0x6e, (byte)0x41, (byte)0x41, (byte)0x4e, unchecked((byte)0xb7), unchecked((byte)0xf8), (byte)0x71, unchecked((byte)0x9c), (byte)0x36, unchecked((byte)0xde), (byte)0x1e, unchecked((byte)0x89), unchecked((byte)0xb4), (byte)0x44, (byte)0x3b, (byte)0x4d, unchecked((byte)0xdb), unchecked((byte)0xc4), unchecked((byte)0x9a), unchecked((byte)0xf4), unchecked((byte)0x89), (byte)0x2b, unchecked((byte)0xcb), unchecked((byte)0x92), unchecked((byte)0x9b), (byte)0x06, unchecked((byte)0x90), (byte)0x69, unchecked((byte)0xd1), unchecked((byte)0x8d), (byte)0x2b, unchecked((byte)0xd1), unchecked((byte)0xa5), unchecked((byte)0xc4), (byte)0x2f, (byte)0x36, unchecked((byte)0xac), unchecked((byte)0xc2), (byte)0x35, (byte)0x59, (byte)0x51, unchecked((byte)0xa8), unchecked((byte)0xd9), unchecked((byte)0xa4), (byte)0x7f, (byte)0x0d, unchecked((byte)0xd4), unchecked((byte)0xbf), (byte)0x02, unchecked((byte)0xe7), (byte)0x1e},
			new byte[] {(byte)0x37, unchecked((byte)0x8f), (byte)0x5a, (byte)0x54, (byte)0x16, (byte)0x31, (byte)0x22, unchecked((byte)0x9b), unchecked((byte)0x94), (byte)0x4c, unchecked((byte)0x9a), unchecked((byte)0xd8), unchecked((byte)0xec), (byte)0x16, (byte)0x5f, unchecked((byte)0xde), (byte)0x3a, (byte)0x7d, (byte)0x3a, (byte)0x1b, (byte)0x25, unchecked((byte)0x89), (byte)0x42, (byte)0x24, (byte)0x3c, unchecked((byte)0xd9), (byte)0x55, unchecked((byte)0xb7), unchecked((byte)0xe0), (byte)0x0d, (byte)0x09, unchecked((byte)0x84), unchecked((byte)0x80), (byte)0x0a, (byte)0x44, (byte)0x0b, unchecked((byte)0xdb), unchecked((byte)0xb2), unchecked((byte)0xce), unchecked((byte)0xb1), (byte)0x7b, (byte)0x2b, unchecked((byte)0x8a), unchecked((byte)0x9a), unchecked((byte)0xa6), (byte)0x07, unchecked((byte)0x9c), (byte)0x54, (byte)0x0e, (byte)0x38, unchecked((byte)0xdc), unchecked((byte)0x92), unchecked((byte)0xcb), (byte)0x1f, (byte)0x2a, (byte)0x60, (byte)0x72, (byte)0x61, (byte)0x44, (byte)0x51, unchecked((byte)0x83), (byte)0x23, (byte)0x5a, unchecked((byte)0xdb)},
			new byte[] {unchecked((byte)0xab), unchecked((byte)0xbe), unchecked((byte)0xde), unchecked((byte)0xa6), unchecked((byte)0x80), (byte)0x05, (byte)0x6f, (byte)0x52, (byte)0x38, (byte)0x2a, unchecked((byte)0xe5), (byte)0x48, unchecked((byte)0xb2), unchecked((byte)0xe4), unchecked((byte)0xf3), unchecked((byte)0xf3), unchecked((byte)0x89), (byte)0x41, unchecked((byte)0xe7), (byte)0x1c, unchecked((byte)0xff), unchecked((byte)0x8a), (byte)0x78, unchecked((byte)0xdb), (byte)0x1f, unchecked((byte)0xff), unchecked((byte)0xe1), unchecked((byte)0x8a), (byte)0x1b, (byte)0x33, (byte)0x61, (byte)0x03, unchecked((byte)0x9f), unchecked((byte)0xe7), (byte)0x67, (byte)0x02, unchecked((byte)0xaf), (byte)0x69, (byte)0x33, (byte)0x4b, (byte)0x7a, (byte)0x1e, (byte)0x6c, (byte)0x30, (byte)0x3b, (byte)0x76, (byte)0x52, unchecked((byte)0xf4), (byte)0x36, unchecked((byte)0x98), unchecked((byte)0xfa), unchecked((byte)0xd1), (byte)0x15, (byte)0x3b, unchecked((byte)0xb6), unchecked((byte)0xc3), (byte)0x74, unchecked((byte)0xb4), unchecked((byte)0xc7), unchecked((byte)0xfb), unchecked((byte)0x98), (byte)0x45, unchecked((byte)0x9c), unchecked((byte)0xed)},
			new byte[] {(byte)0x7b, unchecked((byte)0xcd), unchecked((byte)0x9e), unchecked((byte)0xd0), unchecked((byte)0xef), unchecked((byte)0xc8), unchecked((byte)0x89), unchecked((byte)0xfb), (byte)0x30, (byte)0x02, unchecked((byte)0xc6), unchecked((byte)0xcd), (byte)0x63, (byte)0x5a, unchecked((byte)0xfe), unchecked((byte)0x94), unchecked((byte)0xd8), unchecked((byte)0xfa), (byte)0x6b, unchecked((byte)0xbb), unchecked((byte)0xeb), unchecked((byte)0xab), (byte)0x07, (byte)0x61, (byte)0x20, (byte)0x01, unchecked((byte)0x80), (byte)0x21, (byte)0x14, unchecked((byte)0x84), (byte)0x66, (byte)0x79, unchecked((byte)0x8a), (byte)0x1d, (byte)0x71, unchecked((byte)0xef), unchecked((byte)0xea), (byte)0x48, unchecked((byte)0xb9), unchecked((byte)0xca), unchecked((byte)0xef), unchecked((byte)0xba), unchecked((byte)0xcd), (byte)0x1d, (byte)0x7d, (byte)0x47, (byte)0x6e, unchecked((byte)0x98), unchecked((byte)0xde), unchecked((byte)0xa2), (byte)0x59, (byte)0x4a, unchecked((byte)0xc0), (byte)0x6f, unchecked((byte)0xd8), (byte)0x5d, (byte)0x6b, unchecked((byte)0xca), unchecked((byte)0xa4), unchecked((byte)0xcd), unchecked((byte)0x81), unchecked((byte)0xf3), (byte)0x2d, (byte)0x1b},
			new byte[] {(byte)0x37, unchecked((byte)0x8e), unchecked((byte)0xe7), (byte)0x67, unchecked((byte)0xf1), (byte)0x16, (byte)0x31, unchecked((byte)0xba), unchecked((byte)0xd2), (byte)0x13, unchecked((byte)0x80), unchecked((byte)0xb0), (byte)0x04, (byte)0x49, unchecked((byte)0xb1), (byte)0x7a, unchecked((byte)0xcd), unchecked((byte)0xa4), (byte)0x3c, (byte)0x32, unchecked((byte)0xbc), unchecked((byte)0xdf), (byte)0x1d, (byte)0x77, unchecked((byte)0xf8), (byte)0x20, (byte)0x12, unchecked((byte)0xd4), (byte)0x30, (byte)0x21, unchecked((byte)0x9f), unchecked((byte)0x9b), (byte)0x5d, unchecked((byte)0x80), unchecked((byte)0xef), unchecked((byte)0x9d), (byte)0x18, unchecked((byte)0x91), unchecked((byte)0xcc), unchecked((byte)0x86), unchecked((byte)0xe7), (byte)0x1d, unchecked((byte)0xa4), unchecked((byte)0xaa), unchecked((byte)0x88), unchecked((byte)0xe1), (byte)0x28, (byte)0x52, unchecked((byte)0xfa), unchecked((byte)0xf4), (byte)0x17, unchecked((byte)0xd5), unchecked((byte)0xd9), unchecked((byte)0xb2), (byte)0x1b, unchecked((byte)0x99), (byte)0x48, unchecked((byte)0xbc), unchecked((byte)0x92), (byte)0x4a, unchecked((byte)0xf1), (byte)0x1b, unchecked((byte)0xd7), (byte)0x20}
		};

		private static readonly byte[] Zero = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

		private static readonly long[][] T = new long[][]
		{
			new long[] {unchecked((long)0xE6F87E5C5B711FD0L), 0x258377800924FA16L, unchecked((long)0xC849E07E852EA4A8L), 0x5B4686A18F06C16AL, 0x0B32E9A2D77B416EL, unchecked((long)0xABDA37A467815C66L), unchecked((long)0xF61796A81A686676L), unchecked((long)0xF5DC0B706391954BL), 0x4862F38DB7E64BF1L, unchecked((long)0xFF5C629A68BD85C5L), unchecked((long)0xCB827DA6FCD75795L), 0x66D36DAF69B9F089L, 0x356C9F74483D83B0L, 0x7CBCECB1238C99A1L, 0x36A702AC31C4708DL, unchecked((long)0x9EB6A8D02FBCDFD6L), unchecked((long)0x8B19FA51E5B3AE37L), unchecked((long)0x9CCFB5408A127D0BL), unchecked((long)0xBC0C78B508208F5AL), unchecked((long)0xE533E3842288ECEDL), unchecked((long)0xCEC2C7D377C15FD2L), unchecked((long)0xEC7817B6505D0F5EL), unchecked((long)0xB94CC2C08336871DL), unchecked((long)0x8C205DB4CB0B04ADL), 0x763C855B28A0892FL, 0x588D1B79F6FF3257L, 0x3FECF69E4311933EL, 0x0FC0D39F803A18C9L, unchecked((long)0xEE010A26F5F3AD83L), 0x10EFE8F4411979A6L, 0x5DCDA10C7DE93A10L, 0x4A1BEE1D1248E92CL, 0x53BFF2DB21847339L, unchecked((long)0xB4F50CCFA6A23D09L), 0x5FB4BC9CD84798CDL, unchecked((long)0xE88A2D8B071C56F9L), 0x7F7771695A756A9CL, unchecked((long)0xC5F02E71A0BA1EBCL), unchecked((long)0xA663F9AB4215E672L), 0x2EB19E22DE5FBB78L, 0x0DB9CE0F2594BA14L, unchecked((long)0x82520E6397664D84L), 0x2F031E6A0208EA98L, 0x5C7F2144A1BE6BF0L, 0x7A37CB1CD16362DBL, unchecked((long)0x83E08E2B4B311C64L), unchecked((long)0xCF70479BAB960E32L), unchecked((long)0x856BA986B9DEE71EL), unchecked((long)0xB5478C877AF56CE9L), unchecked((long)0xB8FE42885F61D6FDL), 0x1BDD0156966238C8L, 0x622157923EF8A92EL, unchecked((long)0xFC97FF42114476F8L), unchecked((long)0x9D7D350856452CEBL), 0x4C90C9B0E0A71256L, 0x2308502DFBCB016CL, 0x2D7A03FAA7A64845L, unchecked((long)0xF46E8B38BFC6C4ABL), unchecked((long)0xBDBEF8FDD477DEBAL), 0x3AAC4CEBC8079B79L, unchecked((long)0xF09CB105E8879D0CL), 0x27FA6A10AC8A58CBL, unchecked((long)0x8960E7C1401D0CEAL), 0x1A6F811E4A356928L, unchecked((long)0x90C4FB0773D196FFL), 0x43501A2F609D0A9FL, unchecked((long)0xF7A516E0C63F3796L), 0x1CE4A6B3B8DA9252L, 0x1324752C38E08A9BL, unchecked((long)0xA5A864733BEC154FL), 0x2BF124575549B33FL, unchecked((long)0xD766DB15440DC5C7L), unchecked((long)0xA7D179E39E42B792L), unchecked((long)0xDADF151A61997FD3L), unchecked((long)0x86A0345EC0271423L), 0x38D5517B6DA939A4L, 0x6518F077104003B4L, 0x02791D90A5AEA2DDL, unchecked((long)0x88D267899C4A5D0AL), unchecked((long)0x930F66DF0A2865C2L), 0x4EE9D4204509B08BL, 0x325538916685292AL, 0x412907BFC533A842L, unchecked((long)0xB27E2B62544DC673L), 0x6C5304456295E007L, 0x5AF406E95351908AL, 0x1F2F3B6BC123616FL, unchecked((long)0xC37B09DC5255E5C6L), 0x3967D133B1FE6844L, 0x298839C7F0E711E2L, 0x409B87F71964F9A2L, unchecked((long)0xE938ADC3DB4B0719L), 0x0C0B4E47F9C3EBF4L, 0x5534D576D36B8843L, 0x4610A05AEB8B02D8L, 0x20C3CDF58232F251L, 0x6DE1840DBEC2B1E7L, unchecked((long)0xA0E8DE06B0FA1D08L), 0x7B854B540D34333BL, 0x42E29A67BCCA5B7FL, unchecked((long)0xD8A6088AC437DD0EL), unchecked((long)0xC63BB3A9D943ED81L), 0x21714DBD5E65A3B1L, 0x6761EDE7B5EEA169L, 0x2431F7C8D573ABF6L, unchecked((long)0xD51FC685E1A3671AL), 0x5E063CD40410C92DL, 0x283AB98F2CB04002L, unchecked((long)0x8FEBC06CB2F2F790L), 0x17D64F116FA1D33CL, unchecked((long)0xE07359F1A99EE4AAL), 0x784ED68C74CDC006L, 0x6E2A19D5C73B42DAL, unchecked((long)0x8712B4161C7045C3L), 0x371582E4ED93216DL, unchecked((long)0xACE390414939F6FCL), 0x7EC5F12186223B7CL, unchecked((long)0xC0B094042BAC16FBL), unchecked((long)0xF9D745379A527EBFL), 0x737C3F2EA3B68168L, 0x33E7B8D9BAD278CAL, unchecked((long)0xA9A32A34C22FFEBBL), unchecked((long)0xE48163CCFEDFBD0DL), unchecked((long)0x8E5940246EA5A670L), 0x51C6EF4B842AD1E4L, 0x22BAD065279C508CL, unchecked((long)0xD91488C218608CEEL), 0x319EA5491F7CDA17L, unchecked((long)0xD394E128134C9C60L), 0x094BF43272D5E3B3L, unchecked((long)0x9BF612A5A4AAD791L), unchecked((long)0xCCBBDA43D26FFD0FL), 0x34DE1F3C946AD250L, 0x4F5B5468995EE16BL, unchecked((long)0xDF9FAF6FEA8F7794L), 0x2648EA5870DD092BL, unchecked((long)0xBFC7E56D71D97C67L), unchecked((long)0xDDE6B2FF4F21D549L), 0x3C276B463AE86003L, unchecked((long)0x91767B4FAF86C71FL), 0x68A13E7835D4B9A0L, unchecked((long)0xB68C115F030C9FD4L), 0x141DD2C916582001L, unchecked((long)0x983D8F7DDD5324ACL), 0x64AA703FCC175254L, unchecked((long)0xC2C989948E02B426L), 0x3E5E76D69F46C2DEL, 0x50746F03587D8004L, 0x45DB3D829272F1E5L, 0x60584A029B560BF3L, unchecked((long)0xFBAE58A73FFCDC62L), unchecked((long)0xA15A5E4E6CAD4CE8L), 0x4BA96E55CE1FB8CCL, 0x08F9747AAE82B253L, unchecked((long)0xC102144CF7FB471BL), unchecked((long)0x9F042898F3EB8E36L), 0x068B27ADF2EFFB7AL, unchecked((long)0xEDCA97FE8C0A5EBEL), 0x778E0513F4F7D8CFL, 0x302C2501C32B8BF7L, unchecked((long)0x8D92DDFC175C554DL), unchecked((long)0xF865C57F46052F5FL), unchecked((long)0xEAF3301BA2B2F424L), unchecked((long)0xAA68B7ECBBD60D86L), unchecked((long)0x998F0F350104754CL), 0x0000000000000000L, unchecked((long)0xF12E314D34D0CCECL), 0x710522BE061823B5L, unchecked((long)0xAF280D9930C005C1L), unchecked((long)0x97FD5CE25D693C65L), 0x19A41CC633CC9A15L, unchecked((long)0x95844172F8C79EB8L), unchecked((long)0xDC5432B7937684A9L), unchecked((long)0x9436C13A2490CF58L), unchecked((long)0x802B13F332C8EF59L), unchecked((long)0xC442AE397CED4F5CL), unchecked((long)0xFA1CD8EFE3AB8D82L), unchecked((long)0xF2E5AC954D293FD1L), 0x6AD823E8907A1B7DL, 0x4D2249F83CF043B6L, 0x03CB9DD879F9F33DL, unchecked((long)0xDE2D2F2736D82674L), 0x2A43A41F891EE2DFL, 0x6F98999D1B6C133AL, unchecked((long)0xD4AD46CD3DF436FAL), unchecked((long)0xBB35DF50269825C0L), unchecked((long)0x964FDCAA813E6D85L), unchecked((long)0xEB41B0537EE5A5C4L), 0x0540BA758B160847L, unchecked((long)0xA41AE43BE7BB44AFL), unchecked((long)0xE3B8C429D0671797L), unchecked((long)0x819993BBEE9FBEB9L), unchecked((long)0xAE9A8DD1EC975421L), unchecked((long)0xF3572CDD917E6E31L), 0x6393D7DAE2AFF8CEL, 0x47A2201237DC5338L, unchecked((long)0xA32343DEC903EE35L), 0x79FC56C4A89A91E6L, 0x01B28048DC5751E0L, 0x1296F564E4B7DB7BL, 0x75F7188351597A12L, unchecked((long)0xDB6D9552BDCE2E33L), 0x1E9DBB231D74308FL, 0x520D7293FDD322D9L, unchecked((long)0xE20A44610C304677L), unchecked((long)0xFEEEE2D2B4EAD425L), unchecked((long)0xCA30FDEE20800675L), 0x61EACA4A47015A13L, unchecked((long)0xE74AFE1487264E30L), 0x2CC883B27BF119A5L, 0x1664CF59B3F682DCL, unchecked((long)0xA811AA7C1E78AF5BL), 0x1D5626FB648DC3B2L, unchecked((long)0xB73E9117DF5BCE34L), unchecked((long)0xD05F7CF06AB56F5DL), unchecked((long)0xFD257F0ACD132718L), 0x574DC8E676C52A9EL, 0x0739A7E52EB8AA9AL, 0x5486553E0F3CD9A3L, 0x56FF48AEAA927B7EL, unchecked((long)0xBE756525AD8E2D87L), 0x7D0E6CF9FFDBC841L, 0x3B1ECCA31450CA99L, 0x6913BE30E983E840L, unchecked((long)0xAD511009956EA71CL), unchecked((long)0xB1B5B6BA2DB4354EL), 0x4469BDCA4E25A005L, 0x15AF5281CA0F71E1L, 0x744598CB8D0E2BF2L, 0x593F9B312AA863B7L, unchecked((long)0xEFB38A6E29A4FC63L), 0x6B6AA3A04C2D4A9DL, 0x3D95EB0EE6BF31E3L, unchecked((long)0xA291C3961554BFD5L), 0x18169C8EEF9BCBF5L, 0x115D68BC9D4E2846L, unchecked((long)0xBA875F18FACF7420L), unchecked((long)0xD1EDFCB8B6E23EBDL), unchecked((long)0xB00736F2F1E364AEL), unchecked((long)0x84D929CE6589B6FEL), 0x70B7A2F6DA4F7255L, 0x0E7253D75C6D4929L, 0x04F23A3D574159A7L, 0x0A8069EA0B2C108EL, 0x49D073C56BB11A11L, unchecked((long)0x8AAB7A1939E4FFD7L), unchecked((long)0xCD095A0B0E38ACEFL), unchecked((long)0xC9FB60365979F548L), unchecked((long)0x92BDE697D67F3422L), unchecked((long)0xC78933E10514BC61L), unchecked((long)0xE1C1D9B975C9B54AL), unchecked((long)0xD2266160CF1BCD80L), unchecked((long)0x9A4492ED78FD8671L), unchecked((long)0xB3CCAB2A881A9793L), 0x72CEBF667FE1D088L, unchecked((long)0xD6D45B5D985A9427L)},
			new long[] {unchecked((long)0xC811A8058C3F55DEL), 0x65F5B43196B50619L, unchecked((long)0xF74F96B1D6706E43L), unchecked((long)0x859D1E8BCB43D336L), 0x5AAB8A85CCFA3D84L, unchecked((long)0xF9C7BF99C295FCFDL), unchecked((long)0xA21FD5A1DE4B630FL), unchecked((long)0xCDB3EF763B8B456DL), unchecked((long)0x803F59F87CF7C385L), unchecked((long)0xB27C73BE5F31913CL), unchecked((long)0x98E3AC6633B04821L), unchecked((long)0xBF61674C26B8F818L), 0x0FFBC995C4C130C8L, unchecked((long)0xAAA0862010761A98L), 0x6057F342210116AAL, unchecked((long)0xF63C760C0654CC35L), 0x2DDB45CC667D9042L, unchecked((long)0xBCF45A964BD40382L), 0x68E8A0C3EF3C6F3DL, unchecked((long)0xA7BD92D269FF73BCL), 0x290AE20201ED2287L, unchecked((long)0xB7DE34CDE885818FL), unchecked((long)0xD901EEA7DD61059BL), unchecked((long)0xD6FA273219A03553L), unchecked((long)0xD56F1AE874CCCEC9L), unchecked((long)0xEA31245C2E83F554L), 0x7034555DA07BE499L, unchecked((long)0xCE26D2AC56E7BEF7L), unchecked((long)0xFD161857A5054E38L), 0x6A0E7DA4527436D1L, 0x5BD86A381CDE9FF2L, unchecked((long)0xCAF7756231770C32L), unchecked((long)0xB09AAED9E279C8D0L), 0x5DEF1091C60674DBL, 0x111046A2515E5045L, 0x23536CE4729802FCL, unchecked((long)0xC50CBCF7F5B63CFAL), 0x73A16887CD171F03L, 0x7D2941AFD9F28DBDL, 0x3F5E3EB45A4F3B9DL, unchecked((long)0x84EEFE361B677140L), 0x3DB8E3D3E7076271L, 0x1A3A28F9F20FD248L, 0x7EBC7C75B49E7627L, 0x74E5F293C7EB565CL, 0x18DCF59E4F478BA4L, 0x0C6EF44FA9ADCB52L, unchecked((long)0xC699812D98DAC760L), 0x788B06DC6E469D0EL, unchecked((long)0xFC65F8EA7521EC4EL), 0x30A5F7219E8E0B55L, 0x2BEC3F65BCA57B6BL, unchecked((long)0xDDD04969BAF1B75EL), unchecked((long)0x99904CDBE394EA57L), 0x14B201D1E6EA40F6L, unchecked((long)0xBBB0C08241284ADDL), 0x50F20463BF8F1DFFL, unchecked((long)0xE8D7F93B93CBACB8L), 0x4D8CB68E477C86E8L, unchecked((long)0xC1DD1B3992268E3FL), 0x7C5AA11209D62FCBL, 0x2F3D98ABDB35C9AEL, 0x671369562BFD5FF5L, 0x15C1E16C36CEE280L, 0x1D7EB2EDF8F39B17L, unchecked((long)0xDA94D37DB00DFE01L), unchecked((long)0x877BC3EC760B8ADAL), unchecked((long)0xCB8495DFE153AE44L), 0x05A24773B7B410B3L, 0x12857B783C32ABDFL, unchecked((long)0x8EB770D06812513BL), 0x536739B9D2E3E665L, 0x584D57E271B26468L, unchecked((long)0xD789C78FC9849725L), unchecked((long)0xA935BBFA7D1AE102L), unchecked((long)0x8B1537A3DFA64188L), unchecked((long)0xD0CD5D9BC378DE7AL), 0x4AC82C9A4D80CFB7L, 0x42777F1B83BDB620L, 0x72D2883A1D33BD75L, 0x5E7A2D4BAB6A8F41L, unchecked((long)0xF4DAAB6BBB1C95D9L), unchecked((long)0x905CFFE7FD8D31B6L), unchecked((long)0x83AA6422119B381FL), unchecked((long)0xC0AEFB8442022C49L), unchecked((long)0xA0F908C663033AE3L), unchecked((long)0xA428AF0804938826L), unchecked((long)0xADE41C341A8A53C7L), unchecked((long)0xAE7121EE77E6A85DL), unchecked((long)0xC47F5C4A25929E8CL), unchecked((long)0xB538E9AA55CDD863L), 0x06377AA9DAD8EB29L, unchecked((long)0xA18AE87BB3279895L), 0x6EDFDA6A35E48414L, 0x6B7D9D19825094A7L, unchecked((long)0xD41CFA55A4E86CBFL), unchecked((long)0xE5CAEDC9EA42C59CL), unchecked((long)0xA36C351C0E6FC179L), 0x5181E4DE6FABBF89L, unchecked((long)0xFFF0C530184D17D4L), unchecked((long)0x9D41EB1584045892L), 0x1C0D525028D73961L, unchecked((long)0xF178EC180CA8856AL), unchecked((long)0x9A0571018EF811CDL), 0x4091A27C3EF5EFCCL, 0x19AF15239F6329D2L, 0x347450EFF91EB990L, unchecked((long)0xE11B4A078DD27759L), unchecked((long)0xB9561DE5FC601331L), unchecked((long)0x912F1F5A2DA993C0L), 0x1654DCB65BA2191AL, 0x3E2DDE098A6B99EBL, unchecked((long)0x8A66D71E0F82E3FEL), unchecked((long)0x8C51ADB7D55A08D7L), 0x4533E50F8941FF7FL, 0x02E6DD67BD4859ECL, unchecked((long)0xE068AABA5DF6D52FL), unchecked((long)0xC24826E3FF4A75A5L), 0x6C39070D88ACDDF8L, 0x6486548C4691A46FL, unchecked((long)0xD1BEBD26135C7C0CL), unchecked((long)0xB30F93038F15334AL), unchecked((long)0x82D9849FC1BF9A69L), unchecked((long)0x9C320BA85420FAE4L), unchecked((long)0xFA528243AFF90767L), unchecked((long)0x9ED4D6CFE968A308L), unchecked((long)0xB825FD582C44B147L), unchecked((long)0x9B7691BC5EDCB3BBL), unchecked((long)0xC7EA619048FE6516L), 0x1063A61F817AF233L, 0x47D538683409A693L, 0x63C2CE984C6DED30L, 0x2A9FDFD86C81D91DL, 0x7B1E3B06032A6694L, 0x666089EBFBD9FD83L, 0x0A598EE67375207BL, 0x07449A140AFC495FL, 0x2CA8A571B6593234L, 0x1F986F8A45BBC2FBL, 0x381AA4A050B372C2L, 0x5423A3ADD81FAF3AL, 0x17273C0B8B86BB6CL, unchecked((long)0xFE83258DC869B5A2L), 0x287902BFD1C980F1L, unchecked((long)0xF5A94BD66B3837AFL), unchecked((long)0x88800A79B2CABA12L), 0x55504310083B0D4CL, unchecked((long)0xDF36940E07B9EEB2L), 0x04D1A7CE6790B2C5L, 0x612413FFF125B4DCL, 0x26F12B97C52C124FL, unchecked((long)0x86082351A62F28ACL), unchecked((long)0xEF93632F9937E5E7L), 0x3507B052293A1BE6L, unchecked((long)0xE72C30AE570A9C70L), unchecked((long)0xD3586041AE1425E0L), unchecked((long)0xDE4574B3D79D4CC4L), unchecked((long)0x92BA228040C5685AL), unchecked((long)0xF00B0CA5DC8C271CL), unchecked((long)0xBE1287F1F69C5A6EL), unchecked((long)0xF39E317FB1E0DC86L), 0x495D114020EC342DL, 0x699B407E3F18CD4BL, unchecked((long)0xDCA3A9D46AD51528L), 0x0D1D14F279896924L, 0x0000000000000000L, 0x593EB75FA196C61EL, 0x2E4E78160B116BD8L, 0x6D4AE7B058887F8EL, unchecked((long)0xE65FD013872E3E06L), 0x7A6DDBBBD30EC4E2L, unchecked((long)0xAC97FC89CAAEF1B1L), 0x09CCB33C1E19DBE1L, unchecked((long)0x89F3EAC462EE1864L), 0x7770CF49AA87ADC6L, 0x56C57ECA6557F6D6L, 0x03953DDA6D6CFB9AL, 0x36928D884456E07CL, 0x1EEB8F37959F608DL, 0x31D6179C4EAAA923L, 0x6FAC3AD7E5C02662L, 0x43049FA653991456L, unchecked((long)0xABD3669DC052B8EEL), unchecked((long)0xAF02C153A7C20A2BL), 0x3CCB036E3723C007L, unchecked((long)0x93C9C23D90E1CA2CL), unchecked((long)0xC33BC65E2F6ED7D3L), 0x4CFF56339758249EL, unchecked((long)0xB1E94E64325D6AA6L), 0x37E16D359472420AL, 0x79F8E661BE623F78L, 0x5214D90402C74413L, 0x482EF1FDF0C8965BL, 0x13F69BC5EC1609A9L, 0x0E88292814E592BEL, 0x4E198B542A107D72L, unchecked((long)0xCCC00FCBEBAFE71BL), 0x1B49C844222B703EL, 0x2564164DA840E9D5L, 0x20C6513E1FF4F966L, unchecked((long)0xBAC3203F910CE8ABL), unchecked((long)0xF2EDD1C261C47EF0L), unchecked((long)0x814CB945ACD361F3L), unchecked((long)0x95FEB8944A392105L), 0x5C9CF02C1622D6ADL, unchecked((long)0x971865F3F77178E9L), unchecked((long)0xBD87BA2B9BF0A1F4L), 0x444005B259655D09L, unchecked((long)0xED75BE48247FBC0BL), 0x7596122E17CFF42AL, unchecked((long)0xB44B091785E97A15L), unchecked((long)0x966B854E2755DA9FL), unchecked((long)0xEEE0839249134791L), 0x32432A4623C652B9L, unchecked((long)0xA8465B47AD3E4374L), unchecked((long)0xF8B45F2412B15E8BL), 0x2417F6F078644BA3L, unchecked((long)0xFB2162FE7FDDA511L), 0x4BBBCC279DA46DC1L, 0x0173E0BDD024A276L, 0x22208C59A2BCA08AL, unchecked((long)0x8FC4906DB836F34DL), unchecked((long)0xE4B90D743A6667EAL), 0x7147B5E0705F46EFL, 0x2782CB2A1508B039L, unchecked((long)0xEC065EF5F45B1E7DL), 0x21B5B183CFD05B10L, unchecked((long)0xDBE733C060295C77L), unchecked((long)0x9FA73672394C017EL), unchecked((long)0xCF55321186C31C81L), unchecked((long)0xD8720E1A0D45A7EDL), 0x3B8F997A3DDF8958L, 0x3AFC79C7EDFB2B2EL, unchecked((long)0xE9A4198643EF0ECEL), 0x5F09CDF67B4E2D37L, 0x4F6A6BE9FA34DF04L, unchecked((long)0xB6ADD47038A123F9L), unchecked((long)0x8D224D0A057EAAA1L), unchecked((long)0xC96248B85C1BF7A8L), unchecked((long)0xE3FD9760309A2EB5L), 0x0B2A6E5BA351820DL, unchecked((long)0xEB42C4E1FEA75722L), unchecked((long)0x948D58299A1D8373L), 0x7FCF9CC864BAD451L, unchecked((long)0xA55B4FB5D4B72A50L), 0x08BF5381CE3D7997L, 0x46A6D8D5E42D04E5L, unchecked((long)0xD22B80FC7E308796L), 0x57B69E77B57354A0L, 0x3969441D8097D0B4L, 0x3330CAFBF3E2F0CFL, unchecked((long)0xE28E77DDE0BE8CC3L), 0x62B12E259C494F46L, unchecked((long)0xA6CE726FB9DBD1CAL), 0x41E242C1EED14DBAL, 0x76032FF47AA30FB0L},
			new long[] {0x45B268A93ACDE4CCL, unchecked((long)0xAF7F0BE884549D08L), 0x048354B3C1468263L, unchecked((long)0x925435C2C80EFED2L), unchecked((long)0xEE4E37F27FDFFBA7L), 0x167A33920C60F14DL, unchecked((long)0xFB123B52EA03E584L), 0x4A0CAB53FDBB9007L, unchecked((long)0x9DEAF6380F788A19L), unchecked((long)0xCB48EC558F0CB32AL), unchecked((long)0xB59DC4B2D6FEF7E0L), unchecked((long)0xDCDBCA22F4F3ECB6L), 0x11DF5813549A9C40L, unchecked((long)0xE33FDEDF568ACED3L), unchecked((long)0xA0C1C8124322E9C3L), 0x07A56B8158FA6D0DL, 0x77279579B1E1F3DDL, unchecked((long)0xD9B18B74422AC004L), unchecked((long)0xB8EC2D9FFFABC294L), unchecked((long)0xF4ACF8A82D75914FL), 0x7BBF69B1EF2B6878L, unchecked((long)0xC4F62FAF487AC7E1L), 0x76CE809CC67E5D0CL, 0x6711D88F92E4C14CL, 0x627B99D9243DEDFEL, 0x234AA5C3DFB68B51L, unchecked((long)0x909B1F15262DBF6DL), 0x4F66EA054B62BCB5L, 0x1AE2CF5A52AA6AE8L, unchecked((long)0xBEA053FBD0CE0148L), unchecked((long)0xED6808C0E66314C9L), 0x43FE16CD15A82710L, unchecked((long)0xCD049231A06970F6L), unchecked((long)0xE7BC8A6C97CC4CB0L), 0x337CE835FCB3B9C0L, 0x65DEF2587CC780F3L, 0x52214EDE4132BB50L, unchecked((long)0x95F15E4390F493DFL), unchecked((long)0x870839625DD2E0F1L), 0x41313C1AFB8B66AFL, unchecked((long)0x91720AF051B211BCL), 0x477D427ED4EEA573L, 0x2E3B4CEEF6E3BE25L, unchecked((long)0x82627834EB0BCC43L), unchecked((long)0x9C03E3DD78E724C8L), 0x2877328AD9867DF9L, 0x14B51945E243B0F2L, 0x574B0F88F7EB97E2L, unchecked((long)0x88B6FA989AA4943AL), 0x19C4F068CB168586L, 0x50EE6409AF11FAEFL, 0x7DF317D5C04EABA4L, 0x7A567C5498B4C6A9L, unchecked((long)0xB6BBFB804F42188EL), 0x3CC22BCF3BC5CD0BL, unchecked((long)0xD04336EAAA397713L), unchecked((long)0xF02FAC1BEC33132CL), 0x2506DBA7F0D3488DL, unchecked((long)0xD7E65D6BF2C31A1EL), 0x5EB9B2161FF820F5L, unchecked((long)0x842E0650C46E0F9FL), 0x716BEB1D9E843001L, unchecked((long)0xA933758CAB315ED4L), 0x3FE414FDA2792265L, 0x27C9F1701EF00932L, 0x73A4C1CA70A771BEL, unchecked((long)0x94184BA6E76B3D0EL), 0x40D829FF8C14C87EL, 0x0FBEC3FAC77674CBL, 0x3616A9634A6A9572L, unchecked((long)0x8F139119C25EF937L), unchecked((long)0xF545ED4D5AEA3F9EL), unchecked((long)0xE802499650BA387BL), 0x6437E7BD0B582E22L, unchecked((long)0xE6559F89E053E261L), unchecked((long)0x80AD52E305288DFCL), 0x6DC55A23E34B9935L, unchecked((long)0xDE14E0F51AD0AD09L), unchecked((long)0xC6390578A659865EL), unchecked((long)0x96D7617109487CB1L), unchecked((long)0xE2D6CB3A21156002L), 0x01E915E5779FAED1L, unchecked((long)0xADB0213F6A77DCB7L), unchecked((long)0x9880B76EB9A1A6ABL), 0x5D9F8D248644CF9BL, unchecked((long)0xFD5E4536C5662658L), unchecked((long)0xF1C6B9FE9BACBDFDL), unchecked((long)0xEACD6341BE9979C4L), unchecked((long)0xEFA7221708405576L), 0x510771ECD88E543EL, unchecked((long)0xC2BA51CB671F043DL), 0x0AD482AC71AF5879L, unchecked((long)0xFE787A045CDAC936L), unchecked((long)0xB238AF338E049AEDL), unchecked((long)0xBD866CC94972EE26L), 0x615DA6EBBD810290L, 0x3295FDD08B2C1711L, unchecked((long)0xF834046073BF0AEAL), unchecked((long)0xF3099329758FFC42L), 0x1CAEB13E7DCFA934L, unchecked((long)0xBA2307481188832BL), 0x24EFCE42874CE65CL, 0x0E57D61FB0E9DA1AL, unchecked((long)0xB3D1BAD6F99B343CL), unchecked((long)0xC0757B1C893C4582L), 0x2B510DB8403A9297L, 0x5C7698C1F1DB614AL, 0x3E0D0118D5E68CB4L, unchecked((long)0xD60F488E855CB4CFL), unchecked((long)0xAE961E0DF3CB33D9L), 0x3A8E55AB14A00ED7L, 0x42170328623789C1L, unchecked((long)0x838B6DD19C946292L), unchecked((long)0x895FEF7DED3B3AEBL), unchecked((long)0xCFCBB8E64E4A3149L), 0x064C7E642F65C3DCL, 0x3D2B3E2A4C5A63DAL, 0x5BD3F340A9210C47L, unchecked((long)0xB474D157A1615931L), unchecked((long)0xAC5934DA1DE87266L), 0x6EE365117AF7765BL, unchecked((long)0xC86ED36716B05C44L), unchecked((long)0x9BA6885C201D49C5L), unchecked((long)0xB905387A88346C45L), 0x131072C4BAB9DDFFL, unchecked((long)0xBF49461EA751AF99L), unchecked((long)0xD52977BC1CE05BA1L), unchecked((long)0xB0F785E46027DB52L), 0x546D30BA6E57788CL, 0x305AD707650F56AEL, unchecked((long)0xC987C682612FF295L), unchecked((long)0xA5AB8944F5FBC571L), 0x7ED528E759F244CAL, unchecked((long)0x8DDCBBCE2C7DB888L), unchecked((long)0xAA154ABE328DB1BAL), 0x1E619BE993ECE88BL, 0x09F2BD9EE813B717L, 0x7401AA4B285D1CB3L, 0x21858F143195CAEEL, 0x48C381841398D1B8L, unchecked((long)0xFCB750D3B2F98889L), 0x39A86A998D1CE1B9L, 0x1F888E0CE473465AL, 0x7899568376978716L, 0x02CF2AD7EE2341BFL, unchecked((long)0x85C713B5B3F1A14EL), unchecked((long)0xFF916FE12B4567E7L), 0x7C1A0230B7D10575L, 0x0C98FCC85ECA9BA5L, unchecked((long)0xA3E7F720DA9E06ADL), 0x6A6031A2BBB1F438L, unchecked((long)0x973E74947ED7D260L), 0x2CF4663918C0FF9AL, 0x5F50A7F368678E24L, 0x34D983B4A449D4CDL, 0x68AF1B755592B587L, 0x7F3C3D022E6DEA1BL, unchecked((long)0xABFC5F5B45121F6BL), 0x0D71E92D29553574L, unchecked((long)0xDFFDF5106D4F03D8L), 0x081BA87B9F8C19C6L, unchecked((long)0xDB7EA1A3AC0981BBL), unchecked((long)0xBBCA12AD66172DFAL), 0x79704366010829C7L, 0x179326777BFF5F9CL, 0x0000000000000000L, unchecked((long)0xEB2476A4C906D715L), 0x724DD42F0738DF6FL, unchecked((long)0xB752EE6538DDB65FL), 0x37FFBC863DF53BA3L, unchecked((long)0x8EFA84FCB5C157E6L), unchecked((long)0xE9EB5C73272596AAL), 0x1B0BDABF2535C439L, unchecked((long)0x86E12C872A4D4E20L), unchecked((long)0x9969A28BCE3E087AL), unchecked((long)0xFAFB2EB79D9C4B55L), 0x056A4156B6D92CB2L, 0x5A3AE6A5DEBEA296L, 0x22A3B026A8292580L, 0x53C85B3B36AD1581L, unchecked((long)0xB11E900117B87583L), unchecked((long)0xC51F3A4A3FE56930L), unchecked((long)0xE019E1EDCF3621BDL), unchecked((long)0xEC811D2591FCBA18L), 0x445B7D4C4D524A1DL, unchecked((long)0xA8DA6069DCAEF005L), 0x58F5CC72309DE329L, unchecked((long)0xD4C062596B7FF570L), unchecked((long)0xCE22AD0339D59F98L), 0x591CD99747024DF8L, unchecked((long)0x8B90C5AA03187B54L), unchecked((long)0xF663D27FC356D0F0L), unchecked((long)0xD8589E9135B56ED5L), 0x35309651D3D67A1CL, 0x12F96721CD26732EL, unchecked((long)0xD28C1C3D441A36ACL), 0x492A946164077F69L, 0x2D1D73DC6F5F514BL, 0x6F0A70F40D68D88AL, 0x60B4B30ECA1EAC41L, unchecked((long)0xD36509D83385987DL), 0x0B3D97490630F6A8L, unchecked((long)0x9ECCC90A96C46577L), unchecked((long)0xA20EE2C5AD01A87CL), unchecked((long)0xE49AB55E0E70A3DEL), unchecked((long)0xA4429CA182646BA0L), unchecked((long)0xDA97B446DB962F6AL), unchecked((long)0xCCED87D4D7F6DE27L), 0x2AB8185D37A53C46L, unchecked((long)0x9F25DCEFE15BCBA6L), unchecked((long)0xC19C6EF9FEA3EB53L), unchecked((long)0xA764A3931BD884CEL), 0x2FD2590B817C10F4L, 0x56A21A6D80743933L, unchecked((long)0xE573A0BB79EF0D0FL), 0x155C0CA095DC1E23L, 0x6C2C4FC694D437E4L, 0x10364DF623053291L, unchecked((long)0xDD32DFC7836C4267L), 0x03263F3299BCEF6EL, 0x66F8CD6AE57B6F9DL, unchecked((long)0x8C35AE2B5BE21659L), 0x31B3C2E21290F87FL, unchecked((long)0x93BD2027BF915003L), 0x69460E90220D1B56L, 0x299E276FAE19D328L, 0x63928C3C53A2432FL, 0x7082FEF8E91B9ED0L, unchecked((long)0xBC6F792C3EED40F7L), 0x4C40D537D2DE53DBL, 0x75E8BFAE5FC2B262L, 0x4DA9C0D2A541FD0AL, 0x4E8FFFE03CFD1264L, 0x2620E495696FA7E3L, unchecked((long)0xE1F0F408B8A98F6CL), unchecked((long)0xD1AA230FDDA6D9C2L), unchecked((long)0xC7D0109DD1C6288FL), unchecked((long)0x8A79D04F7487D585L), 0x4694579BA3710BA2L, 0x38417F7CFA834F68L, 0x1D47A4DB0A5007E5L, 0x206C9AF1460A643FL, unchecked((long)0xA128DDF734BD4712L), unchecked((long)0x8144470672B7232DL), unchecked((long)0xF2E086CC02105293L), 0x182DE58DBC892B57L, unchecked((long)0xCAA1F9B0F8931DFBL), 0x6B892447CC2E5AE9L, unchecked((long)0xF9DD11850420A43BL), 0x4BE5BEB68A243ED6L, 0x5584255F19C8D65DL, 0x3B67404E633FA006L, unchecked((long)0xA68DB6766C472A1FL), unchecked((long)0xF78AC79AB4C97E21L), unchecked((long)0xC353442E1080AAECL), unchecked((long)0x9A4F9DB95782E714L)},
			new long[] {0x05BA7BC82C9B3220L, 0x31A54665F8B65E4FL, unchecked((long)0xB1B651F77547F4D4L), unchecked((long)0x8BFA0D857BA46682L), unchecked((long)0x85A96C5AA16A98BBL), unchecked((long)0x990FAEF908EB79C9L), unchecked((long)0xA15E37A247F4A62DL), 0x76857DCD5D27741EL, unchecked((long)0xF8C50B800A1820BCL), unchecked((long)0xBE65DCB201F7A2B4L), 0x666D1B986F9426E7L, 0x4CC921BF53C4E648L, unchecked((long)0x95410A0F93D9CA42L), 0x20CDCCAA647BA4EFL, 0x429A4060890A1871L, 0x0C4EA4F69B32B38BL, unchecked((long)0xCCDA362DDE354CD3L), unchecked((long)0x96DC23BC7C5B2FA9L), unchecked((long)0xC309BB68AA851AB3L), unchecked((long)0xD26131A73648E013L), 0x021DC52941FC4DB2L, unchecked((long)0xCD5ADAB7704BE48AL), unchecked((long)0xA77965D984ED71E6L), 0x32386FD61734BBA4L, unchecked((long)0xE82D6DD538AB7245L), 0x5C2147EA6177B4B1L, 0x5DA1AB70CF091CE8L, unchecked((long)0xAC907FCE72B8BDFFL), 0x57C85DFD972278A8L, unchecked((long)0xA4E44C6A6B6F940DL), 0x3851995B4F1FDFE4L, 0x62578CCAED71BC9EL, unchecked((long)0xD9882BB0C01D2C0AL), unchecked((long)0x917B9D5D113C503BL), unchecked((long)0xA2C31E11A87643C6L), unchecked((long)0xE463C923A399C1CEL), unchecked((long)0xF71686C57EA876DCL), unchecked((long)0x87B4A973E096D509L), unchecked((long)0xAF0D567D9D3A5814L), unchecked((long)0xB40C2A3F59DCC6F4L), 0x3602F88495D121DDL, unchecked((long)0xD3E1DD3D9836484AL), unchecked((long)0xF945E71AA46688E5L), 0x7518547EB2A591F5L, unchecked((long)0x9366587450C01D89L), unchecked((long)0x9EA81018658C065BL), 0x4F54080CBC4603A3L, 0x2D0384C65137BF3DL, unchecked((long)0xDC325078EC861E2AL), unchecked((long)0xEA30A8FC79573FF7L), 0x214D2030CA050CB6L, 0x65F0322B8016C30CL, 0x69BE96DD1B247087L, unchecked((long)0xDB95EE9981E161B8L), unchecked((long)0xD1FC1814D9CA05F8L), unchecked((long)0x820ED2BBCC0DE729L), 0x63D76050430F14C7L, 0x3BCCB0E8A09D3A0FL, unchecked((long)0x8E40764D573F54A2L), 0x39D175C1E16177BDL, 0x12F5A37C734F1F4BL, unchecked((long)0xAB37C12F1FDFC26DL), 0x5648B167395CD0F1L, 0x6C04ED1537BF42A7L, unchecked((long)0xED97161D14304065L), 0x7D6C67DAAB72B807L, unchecked((long)0xEC17FA87BA4EE83CL), unchecked((long)0xDFAF79CB0304FBC1L), 0x733F060571BC463EL, 0x78D61C1287E98A27L, unchecked((long)0xD07CF48E77B4ADA1L), unchecked((long)0xB9C262536C90DD26L), unchecked((long)0xE2449B5860801605L), unchecked((long)0x8FC09AD7F941FCFBL), unchecked((long)0xFAD8CEA94BE46D0EL), unchecked((long)0xA343F28B0608EB9FL), unchecked((long)0x9B126BD04917347BL), unchecked((long)0x9A92874AE7699C22L), 0x1B017C42C4E69EE0L, 0x3A4C5C720EE39256L, 0x4B6E9F5E3EA399DAL, 0x6BA353F45AD83D35L, unchecked((long)0xE7FEE0904C1B2425L), 0x22D009832587E95DL, unchecked((long)0x842980C00F1430E2L), unchecked((long)0xC6B3C0A0861E2893L), 0x087433A419D729F2L, 0x341F3DADD42D6C6FL, unchecked((long)0xEE0A3FAEFBB2A58EL), 0x4AEE73C490DD3183L, unchecked((long)0xAAB72DB5B1A16A34L), unchecked((long)0xA92A04065E238FDFL), 0x7B4B35A1686B6FCCL, 0x6A23BF6EF4A6956CL, 0x191CB96B851AD352L, 0x55D598D4D6DE351AL, unchecked((long)0xC9604DE5F2AE7EF3L), 0x1CA6C2A3A981E172L, unchecked((long)0xDE2F9551AD7A5398L), 0x3025AAFF56C8F616L, 0x15521D9D1E2860D9L, 0x506FE31CFA45073AL, 0x189C55F12B647B0BL, 0x0180EC9AAE7EA859L, 0x7CEC8B40050C105EL, 0x2350E5198BF94104L, unchecked((long)0xEF8AD33455CC0DD7L), 0x07A7BEE16D677F92L, unchecked((long)0xE5E325B90DE76997L), 0x5A061591A26E637AL, unchecked((long)0xB611EF1618208B46L), 0x09F4DF3EB7A981ABL, 0x1EBB078AE87DACC0L, unchecked((long)0xB791038CB65E231FL), 0x0FD38D4574B05660L, 0x67EDF702C1EA8EBEL, unchecked((long)0xBA5F4BE0831238CDL), unchecked((long)0xE3C477C2CEFEBE5CL), 0x0DCE486C354C1BD2L, unchecked((long)0x8C5DB36416C31910L), 0x26EA9ED1A7627324L, 0x039D29B3EF82E5EBL, unchecked((long)0x9F28FC82CBF2AE02L), unchecked((long)0xA8AAE89CF05D2786L), 0x431AACFA2774B028L, unchecked((long)0xCF471F9E31B7A938L), 0x581BD0B8E3922EC8L, unchecked((long)0xBC78199B400BEF06L), unchecked((long)0x90FB71C7BF42F862L), 0x1F3BEB1046030499L, 0x683E7A47B55AD8DEL, unchecked((long)0x988F4263A695D190L), unchecked((long)0xD808C72A6E638453L), 0x0627527BC319D7CBL, unchecked((long)0xEBB04466D72997AEL), unchecked((long)0xE67E0C0AE2658C7CL), 0x14D2F107B056C880L, 0x7122C32C30400B8CL, unchecked((long)0x8A7AE11FD5DACEDBL), unchecked((long)0xA0DEDB38E98A0E74L), unchecked((long)0xAD109354DCC615A6L), 0x0BE91A17F655CC19L, unchecked((long)0x8DDD5FFEB8BDB149L), unchecked((long)0xBFE53028AF890AEDL), unchecked((long)0xD65BA6F5B4AD7A6AL), 0x7956F0882997227EL, 0x10E8665532B352F9L, 0x0E5361DFDACEFE39L, unchecked((long)0xCEC7F3049FC90161L), unchecked((long)0xFF62B561677F5F2EL), unchecked((long)0x975CCF26D22587F0L), 0x51EF0F86543BAF63L, 0x2F1E41EF10CBF28FL, 0x52722635BBB94A88L, unchecked((long)0xAE8DBAE73344F04DL), 0x410769D36688FD9AL, unchecked((long)0xB3AB94DE34BBB966L), unchecked((long)0x801317928DF1AA9BL), unchecked((long)0xA564A0F0C5113C54L), unchecked((long)0xF131D4BEBDB1A117L), 0x7F71A2F3EA8EF5B5L, 0x40878549C8F655C3L, 0x7EF14E6944F05DECL, unchecked((long)0xD44663DCF55137D8L), unchecked((long)0xF2ACFD0D523344FCL), 0x0000000000000000L, 0x5FBC6E598EF5515AL, 0x16CF342EF1AA8532L, unchecked((long)0xB036BD6DDB395C8DL), 0x13754FE6DD31B712L, unchecked((long)0xBBDFA77A2D6C9094L), unchecked((long)0x89E7C8AC3A582B30L), 0x3C6B0E09CDFA459DL, unchecked((long)0xC4AE0589C7E26521L), 0x49735A777F5FD468L, unchecked((long)0xCAFD64561D2C9B18L), unchecked((long)0xDA1502032F9FC9E1L), unchecked((long)0x8867243694268369L), 0x3782141E3BAF8984L, unchecked((long)0x9CB5D53124704BE9L), unchecked((long)0xD7DB4A6F1AD3D233L), unchecked((long)0xA6F989432A93D9BFL), unchecked((long)0x9D3539AB8A0EE3B0L), 0x53F2CAAF15C7E2D1L, 0x6E19283C76430F15L, 0x3DEBE2936384EDC4L, 0x5E3C82C3208BF903L, 0x33B8834CB94A13FDL, 0x6470DEB12E686B55L, 0x359FD1377A53C436L, 0x61CAA57902F35975L, 0x043A975282E59A79L, unchecked((long)0xFD7F70482683129CL), unchecked((long)0xC52EE913699CCD78L), 0x28B9FF0E7DAC8D1DL, 0x5455744E78A09D43L, unchecked((long)0xCB7D88CCB3523341L), 0x44BD121B4A13CFBAL, 0x4D49CD25FDBA4E11L, 0x3E76CB208C06082FL, 0x3FF627BA2278A076L, unchecked((long)0xC28957F204FBB2EAL), 0x453DFE81E46D67E3L, unchecked((long)0x94C1E6953DA7621BL), 0x2C83685CFF491764L, unchecked((long)0xF32C1197FC4DECA5L), 0x2B24D6BD922E68F6L, unchecked((long)0xB22B78449AC5113FL), 0x48F3B6EDD1217C31L, 0x2E9EAD75BEB55AD6L, 0x174FD8B45FD42D6BL, 0x4ED4E4961238ABFAL, unchecked((long)0x92E6B4EEFEBEB5D0L), 0x46A0D7320BEF8208L, 0x47203BA8A5912A51L, 0x24F75BF8E69E3E96L, unchecked((long)0xF0B1382413CF094EL), unchecked((long)0xFEE259FBC901F777L), 0x276A724B091CDB7DL, unchecked((long)0xBDF8F501EE75475FL), 0x599B3C224DEC8691L, 0x6D84018F99C1EAFEL, 0x7498B8E41CDB39ACL, unchecked((long)0xE0595E71217C5BB7L), 0x2AA43A273C50C0AFL, unchecked((long)0xF50B43EC3F543B6EL), unchecked((long)0x838E3E2162734F70L), unchecked((long)0xC09492DB4507FF58L), 0x72BFEA9FDFC2EE67L, 0x11688ACF9CCDFAA0L, 0x1A8190D86A9836B9L, 0x7ACBD93BC615C795L, unchecked((long)0xC7332C3A286080CAL), unchecked((long)0x863445E94EE87D50L), unchecked((long)0xF6966A5FD0D6DE85L), unchecked((long)0xE9AD814F96D5DA1CL), 0x70A22FB69E3EA3D5L, 0x0A69F68D582B6440L, unchecked((long)0xB8428EC9C2EE757FL), 0x604A49E3AC8DF12CL, 0x5B86F90B0C10CB23L, unchecked((long)0xE1D9B2EB8F02F3EEL), 0x29391394D3D22544L, unchecked((long)0xC8E0A17F5CD0D6AAL), unchecked((long)0xB58CC6A5F7A26EADL), unchecked((long)0x8193FB08238F02C2L), unchecked((long)0xD5C68F465B2F9F81L), unchecked((long)0xFCFF9CD288FDBAC5L), 0x77059157F359DC47L, 0x1D262E3907FF492BL, unchecked((long)0xFB582233E59AC557L), unchecked((long)0xDDB2BCE242F8B673L), 0x2577B76248E096CFL, 0x6F99C4A6D83DA74CL, unchecked((long)0xC1147E41EB795701L), unchecked((long)0xF48BAF76912A9337L)},
			new long[] {0x3EF29D249B2C0A19L, unchecked((long)0xE9E16322B6F8622FL), 0x5536994047757F7AL, unchecked((long)0x9F4D56D5A47B0B33L), unchecked((long)0x822567466AA1174CL), unchecked((long)0xB8F5057DEB082FB2L), unchecked((long)0xCC48C10BF4475F53L), 0x373088D4275DEC3AL, unchecked((long)0x968F4325180AED10L), 0x173D232CF7016151L, unchecked((long)0xAE4ED09F946FCC13L), unchecked((long)0xFD4B4741C4539873L), 0x1B5B3F0DD9933765L, 0x2FFCB0967B644052L, unchecked((long)0xE02376D20A89840CL), unchecked((long)0xA3AE3A70329B18D7L), 0x419CBD2335DE8526L, unchecked((long)0xFAFEBF115B7C3199L), 0x0397074F85AA9B0DL, unchecked((long)0xC58AD4FB4836B970L), unchecked((long)0xBEC60BE3FC4104A8L), 0x1EFF36DC4B708772L, 0x131FDC33ED8453B6L, 0x0844E33E341764D3L, 0x0FF11B6EAB38CD39L, 0x64351F0A7761B85AL, 0x3B5694F509CFBA0EL, 0x30857084B87245D0L, 0x47AFB3BD2297AE3CL, unchecked((long)0xF2BA5C2F6F6B554AL), 0x74BDC4761F4F70E1L, unchecked((long)0xCFDFC64471EDC45EL), unchecked((long)0xE610784C1DC0AF16L), 0x7ACA29D63C113F28L, 0x2DED411776A859AFL, unchecked((long)0xAC5F211E99A3D5EEL), unchecked((long)0xD484F949A87EF33BL), 0x3CE36CA596E013E4L, unchecked((long)0xD120F0983A9D432CL), 0x6BC40464DC597563L, 0x69D5F5E5D1956C9EL, unchecked((long)0x9AE95F043698BB24L), unchecked((long)0xC9ECC8DA66A4EF44L), unchecked((long)0xD69508C8A5B2EAC6L), unchecked((long)0xC40C2235C0503B80L), 0x38C193BA8C652103L, 0x1CEEC75D46BC9E8FL, unchecked((long)0xD331011937515AD1L), unchecked((long)0xD8E2E56886ECA50FL), unchecked((long)0xB137108D5779C991L), 0x709F3B6905CA4206L, 0x4FEB50831680CAEFL, unchecked((long)0xEC456AF3241BD238L), 0x58D673AFE181ABBEL, 0x242F54E7CAD9BF8CL, 0x0211F1810DCC19FDL, unchecked((long)0x90BC4DBB0F43C60AL), unchecked((long)0x9518446A9DA0761DL), unchecked((long)0xA1BFCBF13F57012AL), 0x2BDE4F8961E172B5L, 0x27B853A84F732481L, unchecked((long)0xB0B1E643DF1F4B61L), 0x18CC38425C39AC68L, unchecked((long)0xD2B7F7D7BF37D821L), 0x3103864A3014C720L, 0x14AA246372ABFA5CL, 0x6E600DB54EBAC574L, 0x394765740403A3F3L, 0x09C215F0BC71E623L, 0x2A58B947E987F045L, 0x7B4CDF18B477BDD8L, unchecked((long)0x9709B5EB906C6FE0L), 0x73083C268060D90BL, unchecked((long)0xFEDC400E41F9037EL), 0x284948C6E44BE9B8L, 0x728ECAE808065BFBL, 0x06330E9E17492B1AL, 0x5950856169E7294EL, unchecked((long)0xBAE4F4FCE6C4364FL), unchecked((long)0xCA7BCF95E30E7449L), 0x7D7FD186A33E96C2L, 0x52836110D85AD690L, 0x4DFAA1021B4CD312L, unchecked((long)0x913ABB75872544FAL), unchecked((long)0xDD46ECB9140F1518L), 0x3D659A6B1E869114L, unchecked((long)0xC23F2CABD719109AL), unchecked((long)0xD713FE062DD46836L), unchecked((long)0xD0A60656B2FBC1DCL), 0x221C5A79DD909496L, unchecked((long)0xEFD26DBCA1B14935L), 0x0E77EDA0235E4FC9L, unchecked((long)0xCBFD395B6B68F6B9L), 0x0DE0EAEFA6F4D4C4L, 0x0422FF1F1A8532E7L, unchecked((long)0xF969B85EDED6AA94L), 0x7F6E2007AEF28F3FL, 0x3AD0623B81A938FEL, 0x6624EE8B7AADA1A7L, unchecked((long)0xB682E8DDC856607BL), unchecked((long)0xA78CC56F281E2A30L), unchecked((long)0xC79B257A45FAA08DL), 0x5B4174E0642B30B3L, 0x5F638BFF7EAE0254L, 0x4BC9AF9C0C05F808L, unchecked((long)0xCE59308AF98B46AEL), unchecked((long)0x8FC58DA9CC55C388L), unchecked((long)0x803496C7676D0EB1L), unchecked((long)0xF33CAAE1E70DD7BAL), unchecked((long)0xBB6202326EA2B4BFL), unchecked((long)0xD5020F87201871CBL), unchecked((long)0x9D5CA754A9B712CEL), unchecked((long)0x841669D87DE83C56L), unchecked((long)0x8A6184785EB6739FL), 0x420BBA6CB0741E2BL, unchecked((long)0xF12D5B60EAC1CE47L), 0x76AC35F71283691CL, 0x2C6BB7D9FECEDB5FL, unchecked((long)0xFCCDB18F4C351A83L), 0x1F79C012C3160582L, unchecked((long)0xF0ABADAE62A74CB7L), unchecked((long)0xE1A5801C82EF06FCL), 0x67A21845F2CB2357L, 0x5114665F5DF04D9DL, unchecked((long)0xBF40FD2D74278658L), unchecked((long)0xA0393D3FB73183DAL), 0x05A409D192E3B017L, unchecked((long)0xA9FB28CF0B4065F9L), 0x25A9A22942BF3D7CL, unchecked((long)0xDB75E22703463E02L), unchecked((long)0xB326E10C5AB5D06CL), unchecked((long)0xE7968E8295A62DE6L), unchecked((long)0xB973F3B3636EAD42L), unchecked((long)0xDF571D3819C30CE5L), unchecked((long)0xEE549B7229D7CBC5L), 0x12992AFD65E2D146L, unchecked((long)0xF8EF4E9056B02864L), unchecked((long)0xB7041E134030E28BL), unchecked((long)0xC02EDD2ADAD50967L), unchecked((long)0x932B4AF48AE95D07L), 0x6FE6FB7BC6DC4784L, 0x239AACB755F61666L, 0x401A4BEDBDB807D6L, 0x485EA8D389AF6305L, unchecked((long)0xA41BC220ADB4B13DL), 0x753B32B89729F211L, unchecked((long)0x997E584BB3322029L), 0x1D683193CEDA1C7FL, unchecked((long)0xFF5AB6C0C99F818EL), 0x16BBD5E27F67E3A1L, unchecked((long)0xA59D34EE25D233CDL), unchecked((long)0x98F8AE853B54A2D9L), 0x6DF70AFACB105E79L, 0x795D2E99B9BBA425L, unchecked((long)0x8E437B6744334178L), 0x0186F6CE886682F0L, unchecked((long)0xEBF092A3BB347BD2L), unchecked((long)0xBCD7FA62F18D1D55L), unchecked((long)0xADD9D7D011C5571EL), 0x0BD3E471B1BDFFDEL, unchecked((long)0xAA6C2F808EEAFEF4L), 0x5EE57D31F6C880A4L, unchecked((long)0xF50FA47FF044FCA0L), 0x1ADDC9C351F5B595L, unchecked((long)0xEA76646D3352F922L), 0x0000000000000000L, unchecked((long)0x85909F16F58EBEA6L), 0x46294573AAF12CCCL, 0x0A5512BF39DB7D2EL, 0x78DBD85731DD26D5L, 0x29CFBE086C2D6B48L, 0x218B5D36583A0F9BL, 0x152CD2ADFACD78ACL, unchecked((long)0x83A39188E2C795BCL), unchecked((long)0xC3B9DA655F7F926AL), unchecked((long)0x9ECBA01B2C1D89C3L), 0x07B5F8509F2FA9EAL, 0x7EE8D6C926940DCFL, 0x36B67E1AAF3B6ECAL, unchecked((long)0x86079859702425ABL), unchecked((long)0xFB7849DFD31AB369L), 0x4C7C57CC932A51E2L, unchecked((long)0xD96413A60E8A27FFL), 0x263EA566C715A671L, 0x6C71FC344376DC89L, 0x4A4F595284637AF8L, unchecked((long)0xDAF314E98B20BCF2L), 0x572768C14AB96687L, 0x1088DB7C682EC8BBL, unchecked((long)0x887075F9537A6A62L), 0x2E7A4658F302C2A2L, 0x619116DBE582084DL, unchecked((long)0xA87DDE018326E709L), unchecked((long)0xDCC01A779C6997E8L), unchecked((long)0xEDC39C3DAC7D50C8L), unchecked((long)0xA60A33A1A078A8C0L), unchecked((long)0xC1A82BE452B38B97L), 0x3F746BEA134A88E9L, unchecked((long)0xA228CCBEBAFD9A27L), unchecked((long)0xABEAD94E068C7C04L), unchecked((long)0xF48952B178227E50L), 0x5CF48CB0FB049959L, 0x6017E0156DE48ABDL, 0x4438B4F2A73D3531L, unchecked((long)0x8C528AE649FF5885L), unchecked((long)0xB515EF924DFCFB76L), 0x0C661C212E925634L, unchecked((long)0xB493195CC59A7986L), unchecked((long)0x9CDA519A21D1903EL), 0x32948105B5BE5C2DL, 0x194ACE8CD45F2E98L, 0x438D4CA238129CDBL, unchecked((long)0x9B6FA9CABEFE39D4L), unchecked((long)0x81B26009EF0B8C41L), unchecked((long)0xDED1EBF691A58E15L), 0x4E6DA64D9EE6481FL, 0x54B06F8ECF13FD8AL, 0x49D85E1D01C9E1F5L, unchecked((long)0xAFC826511C094EE3L), unchecked((long)0xF698A33075EE67ADL), 0x5AC7822EEC4DB243L, unchecked((long)0x8DD47C28C199DA75L), unchecked((long)0x89F68337DB1CE892L), unchecked((long)0xCDCE37C57C21DDA3L), 0x530597DE503C5460L, 0x6A42F2AA543FF793L, 0x5D727A7E73621BA9L, unchecked((long)0xE232875307459DF1L), 0x56A19E0FC2DFE477L, unchecked((long)0xC61DD3B4CD9C227DL), unchecked((long)0xE5877F03986A341BL), unchecked((long)0x949EB2A415C6F4EDL), 0x6206119460289340L, 0x6380E75AE84E11B0L, unchecked((long)0x8BE772B6D6D0F16FL), 0x50929091D596CF6DL, unchecked((long)0xE86795EC3E9EE0DFL), 0x7CF927482B581432L, unchecked((long)0xC86A3E14EEC26DB4L), 0x7119CDA78DACC0F6L, unchecked((long)0xE40189CD100CB6EBL), unchecked((long)0x92ADBC3A028FDFF7L), unchecked((long)0xB2A017C2D2D3529CL), 0x200DABF8D05C8D6BL, 0x34A78F9BA2F77737L, unchecked((long)0xE3B4719D8F231F01L), 0x45BE423C2F5BB7C1L, unchecked((long)0xF71E55FEFD88E55DL), 0x6853032B59F3EE6EL, 0x65B3E9C4FF073AAAL, 0x772AC3399AE5EBECL, unchecked((long)0x87816E97F842A75BL), 0x110E2DB2E0484A4BL, 0x331277CB3DD8DEDDL, unchecked((long)0xBD510CAC79EB9FA5L), 0x352179552A91F5C7L},
			new long[] {unchecked((long)0x8AB0A96846E06A6DL), 0x43C7E80B4BF0B33AL, 0x08C9B3546B161EE5L, 0x39F1C235EBA990BEL, unchecked((long)0xC1BEF2376606C7B2L), 0x2C209233614569AAL, unchecked((long)0xEB01523B6FC3289AL), unchecked((long)0x946953AB935ACEDDL), 0x272838F63E13340EL, unchecked((long)0x8B0455ECA12BA052L), 0x77A1B2C4978FF8A2L, unchecked((long)0xA55122CA13E54086L), 0x2276135862D3F1CDL, unchecked((long)0xDB8DDFDE08B76CFEL), 0x5D1E12C89E4A178AL, 0x0E56816B03969867L, unchecked((long)0xEE5F79953303ED59L), unchecked((long)0xAFED748BAB78D71DL), 0x6D929F2DF93E53EEL, unchecked((long)0xF5D8A8F8BA798C2AL), unchecked((long)0xF619B1698E39CF6BL), unchecked((long)0x95DDAF2F749104E2L), unchecked((long)0xEC2A9C80E0886427L), unchecked((long)0xCE5C8FD8825B95EAL), unchecked((long)0xC4E0D9993AC60271L), 0x4699C3A5173076F9L, 0x3D1B151F50A29F42L, unchecked((long)0x9ED505EA2BC75946L), 0x34665ACFDC7F4B98L, 0x61B1FB53292342F7L, unchecked((long)0xC721C0080E864130L), unchecked((long)0x8693CD1696FD7B74L), unchecked((long)0x872731927136B14BL), unchecked((long)0xD3446C8A63A1721BL), 0x669A35E8A6680E4AL, unchecked((long)0xCAB658F239509A16L), unchecked((long)0xA4E5DE4EF42E8AB9L), 0x37A7435EE83F08D9L, 0x134E6239E26C7F96L, unchecked((long)0x82791A3C2DF67488L), 0x3F6EF00A8329163CL, unchecked((long)0x8E5A7E42FDEB6591L), 0x5CAAEE4C7981DDB5L, 0x19F234785AF1E80DL, 0x255DDDE3ED98BD70L, 0x50898A32A99CCCACL, 0x28CA4519DA4E6656L, unchecked((long)0xAE59880F4CB31D22L), 0x0D9798FA37D6DB26L, 0x32F968F0B4FFCD1AL, unchecked((long)0xA00F09644F258545L), unchecked((long)0xFA3AD5175E24DE72L), unchecked((long)0xF46C547C5DB24615L), 0x713E80FBFF0F7E20L, 0x7843CF2B73D2AAFAL, unchecked((long)0xBD17EA36AEDF62B4L), unchecked((long)0xFD111BACD16F92CFL), 0x4ABAA7DBC72D67E0L, unchecked((long)0xB3416B5DAD49FAD3L), unchecked((long)0xBCA316B24914A88BL), 0x15D150068AECF914L, unchecked((long)0xE27C1DEBE31EFC40L), 0x4FE48C759BEDA223L, 0x7EDCFD141B522C78L, 0x4E5070F17C26681CL, unchecked((long)0xE696CAC15815F3BCL), 0x35D2A64B3BB481A7L, unchecked((long)0x800CFF29FE7DFDF6L), 0x1ED9FAC3D5BAA4B0L, 0x6C2663A91EF599D1L, 0x03C1199134404341L, unchecked((long)0xF7AD4DED69F20554L), unchecked((long)0xCD9D9649B61BD6ABL), unchecked((long)0xC8C3BDE7EADB1368L), unchecked((long)0xD131899FB02AFB65L), 0x1D18E352E1FAE7F1L, unchecked((long)0xDA39235AEF7CA6C1L), unchecked((long)0xA1BBF5E0A8EE4F7AL), unchecked((long)0x91377805CF9A0B1EL), 0x3138716180BF8E5BL, unchecked((long)0xD9F83ACBDB3CE580L), 0x0275E515D38B897EL, 0x472D3F21F0FBBCC6L, 0x2D946EB7868EA395L, unchecked((long)0xBA3C248D21942E09L), unchecked((long)0xE7223645BFDE3983L), unchecked((long)0xFF64FEB902E41BB1L), unchecked((long)0xC97741630D10D957L), unchecked((long)0xC3CB1722B58D4ECCL), unchecked((long)0xA27AEC719CAE0C3BL), unchecked((long)0x99FECB51A48C15FBL), 0x1465AC826D27332BL, unchecked((long)0xE1BD047AD75EBF01L), 0x79F733AF941960C5L, 0x672EC96C41A3C475L, unchecked((long)0xC27FEBA6524684F3L), 0x64EFD0FD75E38734L, unchecked((long)0xED9E60040743AE18L), unchecked((long)0xFB8E2993B9EF144DL), 0x38453EB10C625A81L, 0x6978480742355C12L, 0x48CF42CE14A6EE9EL, 0x1CAC1FD606312DCEL, 0x7B82D6BA4792E9BBL, unchecked((long)0x9D141C7B1F871A07L), 0x5616B80DC11C4A2EL, unchecked((long)0xB849C198F21FA777L), 0x7CA91801C8D9A506L, unchecked((long)0xB1348E487EC273ADL), 0x41B20D1E987B3A44L, 0x7460AB55A3CFBBE3L, unchecked((long)0x84E628034576F20AL), 0x1B87D16D897A6173L, 0x0FE27DEFE45D5258L, unchecked((long)0x83CDE6B8CA3DBEB7L), 0x0C23647ED01D1119L, 0x7A362A3EA0592384L, unchecked((long)0xB61F40F3F1893F10L), 0x75D457D1440471DCL, 0x4558DA34237035B8L, unchecked((long)0xDCA6116587FC2043L), unchecked((long)0x8D9B67D3C9AB26D0L), 0x2B0B5C88EE0E2517L, 0x6FE77A382AB5DA90L, 0x269CC472D9D8FE31L, 0x63C41E46FAA8CB89L, unchecked((long)0xB7ABBC771642F52FL), 0x7D1DE4852F126F39L, unchecked((long)0xA8C6BA3024339BA0L), 0x600507D7CEE888C8L, unchecked((long)0x8FEE82C61A20AFAEL), 0x57A2448926D78011L, unchecked((long)0xFCA5E72836A458F0L), 0x072BCEBB8F4B4CBDL, 0x497BBE4AF36D24A1L, 0x3CAFE99BB769557DL, 0x12FA9EBD05A7B5A9L, unchecked((long)0xE8C04BAA5B836BDBL), 0x4273148FAC3B7905L, unchecked((long)0x908384812851C121L), unchecked((long)0xE557D3506C55B0FDL), 0x72FF996ACB4F3D61L, 0x3EDA0C8E64E2DC03L, unchecked((long)0xF0868356E6B949E9L), 0x04EAD72ABB0B0FFCL, 0x17A4B5135967706AL, unchecked((long)0xE3C8E16F04D5367FL), unchecked((long)0xF84F30028DAF570CL), 0x1846C8FCBD3A2232L, 0x5B8120F7F6CA9108L, unchecked((long)0xD46FA231ECEA3EA6L), 0x334D947453340725L, 0x58403966C28AD249L, unchecked((long)0xBED6F3A79A9F21F5L), 0x68CCB483A5FE962DL, unchecked((long)0xD085751B57E1315AL), unchecked((long)0xFED0023DE52FD18EL), 0x4B0E5B5F20E6ADDFL, 0x1A332DE96EB1AB4CL, unchecked((long)0xA3CE10F57B65C604L), 0x108F7BA8D62C3CD7L, unchecked((long)0xAB07A3A11073D8E1L), 0x6B0DAD1291BED56CL, unchecked((long)0xF2F366433532C097L), 0x2E557726B2CEE0D4L, 0x0000000000000000L, unchecked((long)0xCB02A476DE9B5029L), unchecked((long)0xE4E32FD48B9E7AC2L), 0x734B65EE2C84F75EL, 0x6E5386BCCD7E10AFL, 0x01B4FC84E7CBCA3FL, unchecked((long)0xCFE8735C65905FD5L), 0x3613BFDA0FF4C2E6L, 0x113B872C31E7F6E8L, 0x2FE18BA255052AEBL, unchecked((long)0xE974B72EBC48A1E4L), 0x0ABC5641B89D979BL, unchecked((long)0xB46AA5E62202B66EL), 0x44EC26B0C4BBFF87L, unchecked((long)0xA6903B5B27A503C7L), 0x7F680190FC99E647L, unchecked((long)0x97A84A3AA71A8D9CL), unchecked((long)0xDD12EDE16037EA7CL), unchecked((long)0xC554251DDD0DC84EL), unchecked((long)0x88C54C7D956BE313L), 0x4D91696048662B5DL, unchecked((long)0xB08072CC9909B992L), unchecked((long)0xB5DE5962C5C97C51L), unchecked((long)0x81B803AD19B637C9L), unchecked((long)0xB2F597D94A8230ECL), 0x0B08AAC55F565DA4L, unchecked((long)0xF1327FD2017283D6L), unchecked((long)0xAD98919E78F35E63L), 0x6AB9519676751F53L, 0x24E921670A53774FL, unchecked((long)0xB9FD3D1C15D46D48L), unchecked((long)0x92F66194FBDA485FL), 0x5A35DC7311015B37L, unchecked((long)0xDED3F4705477A93DL), unchecked((long)0xC00A0EB381CD0D8DL), unchecked((long)0xBB88D809C65FE436L), 0x16104997BEACBA55L, 0x21B70AC95693B28CL, 0x59F4C5E225411876L, unchecked((long)0xD5DB5EB50B21F499L), 0x55D7A19CF55C096FL, unchecked((long)0xA97246B4C3F8519FL), unchecked((long)0x8552D487A2BD3835L), 0x54635D181297C350L, 0x23C2EFDC85183BF2L, unchecked((long)0x9F61F96ECC0C9379L), 0x534893A39DDC8FEDL, 0x5EDF0B59AA0A54CBL, unchecked((long)0xAC2C6D1A9F38945CL), unchecked((long)0xD7AEBBA0D8AA7DE7L), 0x2ABFA00C09C5EF28L, unchecked((long)0xD84CC64F3CF72FBFL), 0x2003F64DB15878B3L, unchecked((long)0xA724C7DFC06EC9F8L), 0x069F323F68808682L, unchecked((long)0xCC296ACD51D01C94L), 0x055E2BAE5CC0C5C3L, 0x6270E2C21D6301B6L, 0x3B842720382219C0L, unchecked((long)0xD2F0900E846AB824L), 0x52FC6F277A1745D2L, unchecked((long)0xC6953C8CE94D8B0FL), unchecked((long)0xE009F8FE3095753EL), 0x655B2C7992284D0BL, unchecked((long)0x984A37D54347DFC4L), unchecked((long)0xEAB5AEBF8808E2A5L), unchecked((long)0x9A3FD2C090CC56BAL), unchecked((long)0x9CA0E0FFF84CD038L), 0x4C2595E4AFADE162L, unchecked((long)0xDF6708F4B3BC6302L), unchecked((long)0xBF620F237D54EBCAL), unchecked((long)0x93429D101C118260L), 0x097D4FD08CDDD4DAL, unchecked((long)0x8C2F9B572E60ECEFL), 0x708A7C7F18C4B41FL, 0x3A30DBA4DFE9D3FFL, 0x4006F19A7FB0F07BL, 0x5F6BF7DD4DC19EF4L, 0x1F6D064732716E8FL, unchecked((long)0xF9FBCC866A649D33L), 0x308C8DE567744464L, unchecked((long)0x8971B0F972A0292CL), unchecked((long)0xD61A47243F61B7D8L), unchecked((long)0xEFEB8511D4C82766L), unchecked((long)0x961CB6BE40D147A3L), unchecked((long)0xAAB35F25F7B812DEL), 0x76154E407044329DL, 0x513D76B64E570693L, unchecked((long)0xF3479AC7D2F90AA8L), unchecked((long)0x9B8B2E4477079C85L), 0x297EB99D3D85AC69L},
			new long[] {0x7E37E62DFC7D40C3L, 0x776F25A4EE939E5BL, unchecked((long)0xE045C850DD8FB5ADL), unchecked((long)0x86ED5BA711FF1952L), unchecked((long)0xE91D0BD9CF616B35L), 0x37E0AB256E408FFBL, unchecked((long)0x9607F6C031025A7AL), 0x0B02F5E116D23C9DL, unchecked((long)0xF3D8486BFB50650CL), 0x621CFF27C40875F5L, 0x7D40CB71FA5FD34AL, 0x6DAA6616DAA29062L, unchecked((long)0x9F5F354923EC84E2L), unchecked((long)0xEC847C3DC507C3B3L), 0x025A3668043CE205L, unchecked((long)0xA8BF9E6C4DAC0B19L), unchecked((long)0xFA808BE2E9BEBB94L), unchecked((long)0xB5B99C5277C74FA3L), 0x78D9BC95F0397BCCL, unchecked((long)0xE332E50CDBAD2624L), unchecked((long)0xC74FCE129332797EL), 0x1729ECEB2EA709ABL, unchecked((long)0xC2D6B9F69954D1F8L), 0x5D898CBFBAB8551AL, unchecked((long)0x859A76FB17DD8ADBL), 0x1BE85886362F7FB5L, unchecked((long)0xF6413F8FF136CD8AL), unchecked((long)0xD3110FA5BBB7E35CL), 0x0A2FEED514CC4D11L, unchecked((long)0xE83010EDCD7F1AB9L), unchecked((long)0xA1E75DE55F42D581L), unchecked((long)0xEEDE4A55C13B21B6L), unchecked((long)0xF2F5535FF94E1480L), 0x0CC1B46D1888761EL, unchecked((long)0xBCE15FDB6529913BL), 0x2D25E8975A7181C2L, 0x71817F1CE2D7A554L, 0x2E52C5CB5C53124BL, unchecked((long)0xF9F7A6BEEF9C281DL), unchecked((long)0x9E722E7D21F2F56EL), unchecked((long)0xCE170D9B81DCA7E6L), 0x0E9B82051CB4941BL, 0x1E712F623C49D733L, 0x21E45CFA42F9F7DCL, unchecked((long)0xCB8E7A7F8BBA0F60L), unchecked((long)0x8E98831A010FB646L), 0x474CCF0D8E895B23L, unchecked((long)0xA99285584FB27A95L), unchecked((long)0x8CC2B57205335443L), 0x42D5B8E984EFF3A5L, 0x012D1B34021E718CL, 0x57A6626AAE74180BL, unchecked((long)0xFF19FC06E3D81312L), 0x35BA9D4D6A7C6DFEL, unchecked((long)0xC9D44C178F86ED65L), 0x506523E6A02E5288L, 0x03772D5C06229389L, unchecked((long)0x8B01F4FE0B691EC0L), unchecked((long)0xF8DABD8AED825991L), 0x4C4E3AEC985B67BEL, unchecked((long)0xB10DF0827FBF96A9L), 0x6A69279AD4F8DAE1L, unchecked((long)0xE78689DCD3D5FF2EL), unchecked((long)0x812E1A2B1FA553D1L), unchecked((long)0xFBAD90D6EBA0CA18L), 0x1AC543B234310E39L, 0x1604F7DF2CB97827L, unchecked((long)0xA6241C6951189F02L), 0x753513CCEAAF7C5EL, 0x64F2A59FC84C4EFAL, 0x247D2B1E489F5F5AL, unchecked((long)0xDB64D718AB474C48L), 0x79F4A7A1F2270A40L, 0x1573DA832A9BEBAEL, 0x3497867968621C72L, 0x514838D2A2302304L, unchecked((long)0xF0AF6537FD72F685L), 0x1D06023E3A6B44BAL, 0x678588C3CE6EDD73L, 0x66A893F7CC70ACFFL, unchecked((long)0xD4D24E29B5EDA9DFL), 0x3856321470EA6A6CL, 0x07C3418C0E5A4A83L, 0x2BCBB22F5635BACDL, 0x04B46CD00878D90AL, 0x06EE5AB80C443B0FL, 0x3B211F4876C8F9E5L, 0x0958C38912EEDE98L, unchecked((long)0xD14B39CDBF8B0159L), 0x397B292072F41BE0L, unchecked((long)0x87C0409313E168DEL), unchecked((long)0xAD26E98847CAA39FL), 0x4E140C849C6785BBL, unchecked((long)0xD5FF551DB7F3D853L), unchecked((long)0xA0CA46D15D5CA40DL), unchecked((long)0xCD6020C787FE346FL), unchecked((long)0x84B76DCF15C3FB57L), unchecked((long)0xDEFDA0FCA121E4CEL), 0x4B8D7B6096012D3DL, unchecked((long)0x9AC642AD298A2C64L), 0x0875D8BD10F0AF14L, unchecked((long)0xB357C6EA7B8374ACL), 0x4D6321D89A451632L, unchecked((long)0xEDA96709C719B23FL), unchecked((long)0xF76C24BBF328BC06L), unchecked((long)0xC662D526912C08F2L), 0x3CE25EC47892B366L, unchecked((long)0xB978283F6F4F39BDL), unchecked((long)0xC08C8F9E9D6833FDL), 0x4F3917B09E79F437L, 0x593DE06FB2C08C10L, unchecked((long)0xD6887841B1D14BDAL), 0x19B26EEE32139DB0L, unchecked((long)0xB494876675D93E2FL), unchecked((long)0x825937771987C058L), unchecked((long)0x90E9AC783D466175L), unchecked((long)0xF1827E03FF6C8709L), unchecked((long)0x945DC0A8353EB87FL), 0x4516F9658AB5B926L, 0x3F9573987EB020EFL, unchecked((long)0xB855330B6D514831L), 0x2AE6A91B542BCB41L, 0x6331E413C6160479L, 0x408F8E8180D311A0L, unchecked((long)0xEFF35161C325503AL), unchecked((long)0xD06622F9BD9570D5L), unchecked((long)0x8876D9A20D4B8D49L), unchecked((long)0xA5533135573A0C8BL), unchecked((long)0xE168D364DF91C421L), unchecked((long)0xF41B09E7F50A2F8FL), 0x12B09B0F24C1A12DL, unchecked((long)0xDA49CC2CA9593DC4L), 0x1F5C34563E57A6BFL, 0x54D14F36A8568B82L, unchecked((long)0xAF7CDFE043F6419AL), unchecked((long)0xEA6A2685C943F8BCL), unchecked((long)0xE5DCBFB4D7E91D2BL), unchecked((long)0xB27ADDDE799D0520L), 0x6B443CAED6E6AB6DL, 0x7BAE91C9F61BE845L, 0x3EB868AC7CAE5163L, 0x11C7B65322E332A4L, unchecked((long)0xD23C1491B9A992D0L), unchecked((long)0x8FB5982E0311C7CAL), 0x70AC6428E0C9D4D8L, unchecked((long)0x895BC2960F55FCC5L), 0x76423E90EC8DEFD7L, 0x6FF0507EDE9E7267L, 0x3DCF45F07A8CC2EAL, 0x4AA06054941F5CB1L, 0x5810FB5BB0DEFD9CL, 0x5EFEA1E3BC9AC693L, 0x6EDD4B4ADC8003EBL, 0x741808F8E8B10DD2L, 0x145EC1B728859A22L, 0x28BC9F7350172944L, 0x270A06424EBDCCD3L, unchecked((long)0x972AEDF4331C2BF6L), 0x059977E40A66A886L, 0x2550302A4A812ED6L, unchecked((long)0xDD8A8DA0A7037747L), unchecked((long)0xC515F87A970E9B7BL), 0x3023EAA9601AC578L, unchecked((long)0xB7E3AA3A73FBADA6L), 0x0FB699311EAAE597L, 0x0000000000000000L, 0x310EF19D6204B4F4L, 0x229371A644DB6455L, 0x0DECAF591A960792L, 0x5CA4978BB8A62496L, 0x1C2B190A38753536L, 0x41A295B582CD602CL, 0x3279DCC16426277DL, unchecked((long)0xC1A194AA9F764271L), 0x139D803B26DFD0A1L, unchecked((long)0xAE51C4D441E83016L), unchecked((long)0xD813FA44AD65DFC1L), unchecked((long)0xAC0BF2BC45D4D213L), 0x23BE6A9246C515D9L, 0x49D74D08923DCF38L, unchecked((long)0x9D05032127D066E7L), 0x2F7FDEFF5E4D63C7L, unchecked((long)0xA47E2A0155247D07L), unchecked((long)0x99B16FF12FA8BFEDL), 0x4661D4398C972AAFL, unchecked((long)0xDFD0BBC8A33F9542L), unchecked((long)0xDCA79694A51D06CBL), unchecked((long)0xB020EBB67DA1E725L), unchecked((long)0xBA0F0563696DAA34L), unchecked((long)0xE4F1A480D5F76CA7L), unchecked((long)0xC438E34E9510EAF7L), unchecked((long)0x939E81243B64F2FCL), unchecked((long)0x8DEFAE46072D25CFL), 0x2C08F3A3586FF04EL, unchecked((long)0xD7A56375B3CF3A56L), 0x20C947CE40E78650L, 0x43F8A3DD86F18229L, 0x568B795EAC6A6987L, unchecked((long)0x8003011F1DBB225DL), unchecked((long)0xF53612D3F7145E03L), 0x189F75DA300DEC3CL, unchecked((long)0x9570DB9C3720C9F3L), unchecked((long)0xBB221E576B73DBB8L), 0x72F65240E4F536DDL, 0x443BE25188ABC8AAL, unchecked((long)0xE21FFE38D9B357A8L), unchecked((long)0xFD43CA6EE7E4F117L), unchecked((long)0xCAA3614B89A47EECL), unchecked((long)0xFE34E732E1C6629EL), unchecked((long)0x83742C431B99B1D4L), unchecked((long)0xCF3A16AF83C2D66AL), unchecked((long)0xAAE5A8044990E91CL), 0x26271D764CA3BD5FL, unchecked((long)0x91C4B74C3F5810F9L), 0x7C6DD045F841A2C6L, 0x7F1AFD19FE63314FL, unchecked((long)0xC8F957238D989CE9L), unchecked((long)0xA709075D5306EE8EL), 0x55FC5402AA48FA0EL, 0x48FA563C9023BEB4L, 0x65DFBEABCA523F76L, 0x6C877D22D8BCE1EEL, unchecked((long)0xCC4D3BF385E045E3L), unchecked((long)0xBEBB69B36115733EL), 0x10EAAD6720FD4328L, unchecked((long)0xB6CEB10E71E5DC2AL), unchecked((long)0xBDCC44EF6737E0B7L), 0x523F158EA412B08DL, unchecked((long)0x989C74C52DB6CE61L), unchecked((long)0x9BEB59992B945DE8L), unchecked((long)0x8A2CEFCA09776F4CL), unchecked((long)0xA3BD6B8D5B7E3784L), unchecked((long)0xEB473DB1CB5D8930L), unchecked((long)0xC3FBA2C29B4AA074L), unchecked((long)0x9C28181525CE176BL), 0x683311F2D0C438E4L, 0x5FD3BAD7BE84B71FL, unchecked((long)0xFC6ED15AE5FA809BL), 0x36CDB0116C5EFE77L, 0x29918447520958C8L, unchecked((long)0xA29070B959604608L), 0x53120EBAA60CC101L, 0x3A0C047C74D68869L, 0x691E0AC6D2DA4968L, 0x73DB4974E6EB4751L, 0x7A838AFDF40599C9L, 0x5A4ACD33B4E21F99L, 0x6046C94FC03497F0L, unchecked((long)0xE6AB92E8D1CB8EA2L), 0x3354C7F5663856F1L, unchecked((long)0xD93EE170AF7BAE4DL), 0x616BD27BC22AE67CL, unchecked((long)0x92B39A10397A8370L), unchecked((long)0xABC8B3304B8E9890L), unchecked((long)0xBF967287630B02B2L), 0x5B67D607B6FC6E15L},
			new long[] {unchecked((long)0xD031C397CE553FE6L), 0x16BA5B01B006B525L, unchecked((long)0xA89BADE6296E70C8L), 0x6A1F525D77D3435BL, 0x6E103570573DFA0BL, 0x660EFB2A17FC95ABL, 0x76327A9E97634BF6L, 0x4BAD9D6462458BF5L, unchecked((long)0xF1830CAEDBC3F748L), unchecked((long)0xC5C8F542669131FFL), unchecked((long)0x95044A1CDC48B0CBL), unchecked((long)0x892962DF3CF8B866L), unchecked((long)0xB0B9E208E930C135L), unchecked((long)0xA14FB3F0611A767CL), unchecked((long)0x8D2605F21C160136L), unchecked((long)0xD6B71922FECC549EL), 0x37089438A5907D8BL, 0x0B5DA38E5803D49CL, 0x5A5BCC9CEA6F3CBCL, unchecked((long)0xEDAE246D3B73FFE5L), unchecked((long)0xD2B87E0FDE22EDCEL), 0x5E54ABB1CA8185ECL, 0x1DE7F88FE80561B9L, unchecked((long)0xAD5E1A870135A08CL), 0x2F2ADBD665CECC76L, 0x5780B5A782F58358L, 0x3EDC8A2EEDE47B3FL, unchecked((long)0xC9D95C3506BEE70FL), unchecked((long)0x83BE111D6C4E05EEL), unchecked((long)0xA603B90959367410L), 0x103C81B4809FDE5DL, 0x2C69B6027D0C774AL, 0x399080D7D5C87953L, 0x09D41E16487406B4L, unchecked((long)0xCDD63B1826505E5FL), unchecked((long)0xF99DC2F49B0298E8L), unchecked((long)0x9CD0540A943CB67FL), unchecked((long)0xBCA84B7F891F17C5L), 0x723D1DB3B78DF2A6L, 0x78AA6E71E73B4F2EL, 0x1433E699A071670DL, unchecked((long)0x84F21BE454620782L), unchecked((long)0x98DF3327B4D20F2FL), unchecked((long)0xF049DCE2D3769E5CL), unchecked((long)0xDB6C60199656EB7AL), 0x648746B2078B4783L, 0x32CD23598DCBADCFL, 0x1EA4955BF0C7DA85L, unchecked((long)0xE9A143401B9D46B5L), unchecked((long)0xFD92A5D9BBEC21B8L), unchecked((long)0xC8138C790E0B8E1BL), 0x2EE00B9A6D7BA562L, unchecked((long)0xF85712B893B7F1FCL), unchecked((long)0xEB28FED80BEA949DL), 0x564A65EB8A40EA4CL, 0x6C9988E8474A2823L, 0x4535898B121D8F2DL, unchecked((long)0xABD8C03231ACCBF4L), unchecked((long)0xBA2E91CAB9867CBDL), 0x7960BE3DEF8E263AL, 0x0C11A977602FD6F0L, unchecked((long)0xCB50E1AD16C93527L), unchecked((long)0xEAE22E94035FFD89L), 0x2866D12F5DE2CE1AL, unchecked((long)0xFF1B1841AB9BF390L), unchecked((long)0x9F9339DE8CFE0D43L), unchecked((long)0x964727C8C48A0BF7L), 0x524502C6AAAE531CL, unchecked((long)0x9B9C5EF3AC10B413L), 0x4FA2FA4942AB32A5L, 0x3F165A62E551122BL, unchecked((long)0xC74148DA76E6E3D7L), unchecked((long)0x924840E5E464B2A7L), unchecked((long)0xD372AE43D69784DAL), 0x233B72A105E11A86L, unchecked((long)0xA48A04914941A638L), unchecked((long)0xB4B68525C9DE7865L), unchecked((long)0xDDEABAACA6CF8002L), 0x0A9773C250B6BD88L, unchecked((long)0xC284FFBB5EBD3393L), unchecked((long)0x8BA0DF472C8F6A4EL), 0x2AEF6CB74D951C32L, 0x427983722A318D41L, 0x73F7CDFFBF389BB2L, 0x074C0AF9382C026CL, unchecked((long)0x8A6A0F0B243A035AL), 0x6FDAE53C5F88931FL, unchecked((long)0xC68B98967E538AC3L), 0x44FF59C71AA8E639L, unchecked((long)0xE2FCE0CE439E9229L), unchecked((long)0xA20CDE2479D8CD40L), 0x19E89FA2C8EBD8E9L, unchecked((long)0xF446BBCFF398270CL), 0x43B3533E2284E455L, unchecked((long)0xD82F0DCD8E945046L), 0x51066F12B26CE820L, unchecked((long)0xE73957AF6BC5426DL), 0x081ECE5A40C16FA0L, 0x3B193D4FC5BFAB7BL, 0x7FE66488DF174D42L, 0x0E9814EF705804D8L, unchecked((long)0x8137AC857C39D7C6L), unchecked((long)0xB1733244E185A821L), 0x695C3F896F11F867L, unchecked((long)0xF6CF0657E3EFF524L), 0x1AABF276D02963D5L, 0x2DA3664E75B91E5EL, 0x0289BD981077D228L, unchecked((long)0x90C1FD7DF413608FL), 0x3C5537B6FD93A917L, unchecked((long)0xAA12107E3919A2E0L), 0x0686DAB530996B78L, unchecked((long)0xDAA6B0559EE3826EL), unchecked((long)0xC34E2FF756085A87L), 0x6D5358A44FFF4137L, unchecked((long)0xFC587595B35948ACL), 0x7CA5095CC7D5F67EL, unchecked((long)0xFB147F6C8B754AC0L), unchecked((long)0xBFEB26AB91DDACF9L), 0x6896EFC567A49173L, unchecked((long)0xCA9A31E11E7C5C33L), unchecked((long)0xBBE44186B13315A9L), 0x0DDB793B689ABFE4L, 0x70B4A02BA7FA208EL, unchecked((long)0xE47A3A7B7307F951L), unchecked((long)0x8CECD5BE14A36822L), unchecked((long)0xEEED49B923B144D9L), 0x17708B4DB8B3DC31L, 0x6088219F2765FED3L, unchecked((long)0xB3FA8FDCF1F27A09L), unchecked((long)0x910B2D31FCA6099BL), 0x0F52C4A378ED6DCCL, 0x50CCBF5EBAD98134L, 0x6BD582117F662A4FL, unchecked((long)0x94CE9A50D4FDD9DFL), 0x2B25BCFB45207526L, 0x67C42B661F49FCBFL, 0x492420FC723259DDL, 0x03436DD418C2BB3CL, 0x1F6E4517F872B391L, unchecked((long)0xA08563BC69AF1F68L), unchecked((long)0xD43EA4BAEEBB86B6L), 0x01CAD04C08B56914L, unchecked((long)0xAC94CACB0980C998L), 0x54C3D8739A373864L, 0x26FEC5C02DBACAC2L, unchecked((long)0xDEA9D778BE0D3B3EL), 0x040F672D20EEB950L, unchecked((long)0xE5B0EA377BB29045L), unchecked((long)0xF30AB136CBB42560L), 0x62019C0737122CFBL, unchecked((long)0xE86B930C13282FA1L), unchecked((long)0xCC1CEB542EE5374BL), 0x538FD28AA21B3A08L, 0x1B61223AD89C0AC1L, 0x36C24474AD25149FL, 0x7A23D3E9F74C9D06L, unchecked((long)0xBE21F6E79968C5EDL), unchecked((long)0xCF5F868036278C77L), unchecked((long)0xF705D61BEB5A9C30L), 0x4D2B47D152DCE08DL, 0x5F9E7BFDC234ECF8L, 0x247778583DCD18EAL, unchecked((long)0x867BA67C4415D5AAL), 0x4CE1979D5A698999L, 0x0000000000000000L, unchecked((long)0xEC64F42133C696F1L), unchecked((long)0xB57C5569C16B1171L), unchecked((long)0xC1C7926F467F88AFL), 0x654D96FE0F3E2E97L, 0x15F936D5A8C40E19L, unchecked((long)0xB8A72C52A9F1AE95L), unchecked((long)0xA9517DAA21DB19DCL), 0x58D27104FA18EE94L, 0x5918A148F2AD8780L, 0x5CDD1629DAF657C4L, unchecked((long)0x8274C15164FB6CFAL), unchecked((long)0xD1FB13DBC6E056F2L), 0x7D6FD910CF609F6AL, unchecked((long)0xB63F38BDD9A9AA4DL), 0x3D9FE7FAF526C003L, 0x74BBC706871499DEL, unchecked((long)0xDF630734B6B8522AL), 0x3AD3ED03CD0AC26FL, unchecked((long)0xFADEAF2083C023D4L), unchecked((long)0xC00D42234ECAE1BBL), unchecked((long)0x8538CBA85CD76E96L), unchecked((long)0xC402250E6E2458EBL), 0x47BC3413026A5D05L, unchecked((long)0xAFD7A71F114272A4L), unchecked((long)0x978DF784CC3F62E3L), unchecked((long)0xB96DFC1EA144C781L), 0x21B2CF391596C8AEL, 0x318E4E8D950916F3L, unchecked((long)0xCE9556CC3E92E563L), 0x385A509BDD7D1047L, 0x358129A0B5E7AFA3L, unchecked((long)0xE6F387E363702B79L), unchecked((long)0xE0755D5653E94001L), 0x7BE903A5FFF9F412L, 0x12B53C2C90E80C75L, 0x3307F315857EC4DBL, unchecked((long)0x8FAFB86A0C61D31EL), unchecked((long)0xD9E5DD8186213952L), 0x77F8AAD29FD622E2L, 0x25BDA814357871FEL, 0x7571174A8FA1F0CAL, 0x137FEC60985D6561L, 0x30449EC19DBC7FE7L, unchecked((long)0xA540D4DD41F4CF2CL), unchecked((long)0xDC206AE0AE7AE916L), 0x5B911CD0E2DA55A8L, unchecked((long)0xB2305F90F947131DL), 0x344BF9ECBD52C6B7L, 0x5D17C665D2433ED0L, 0x18224FEEC05EB1FDL, unchecked((long)0x9E59E992844B6457L), unchecked((long)0x9A568EBFA4A5DD07L), unchecked((long)0xA3C60E68716DA454L), 0x7E2CB4C4D7A22456L, unchecked((long)0x87B176304CA0BCBEL), 0x413AEEA632F3367DL, unchecked((long)0x9915E36BBC67663BL), 0x40F03EEA3A465F69L, 0x1C2D28C3E0B008ADL, 0x4E682A054A1E5BB1L, 0x05C5B761285BD044L, unchecked((long)0xE1BF8D1A5B5C2915L), unchecked((long)0xF2C0617AC3014C74L), unchecked((long)0xB7F5E8F1D11CC359L), 0x63CB4C4B3FA745EFL, unchecked((long)0x9D1A84469C89DF6BL), unchecked((long)0xE33630824B2BFB3DL), unchecked((long)0xD5F474F6E60EEFA2L), unchecked((long)0xF58C6B83FB2D4E18L), 0x4676E45F0ADF3411L, 0x20781F751D23A1BAL, unchecked((long)0xBD629B3381AA7ED1L), unchecked((long)0xAE1D775319F71BB0L), unchecked((long)0xFED1C80DA32E9A84L), 0x5509083F92825170L, 0x29AC01635557A70EL, unchecked((long)0xA7C9694551831D04L), unchecked((long)0x8E65682604D4BA0AL), 0x11F651F8882AB749L, unchecked((long)0xD77DC96EF6793D8AL), unchecked((long)0xEF2799F52B042DCDL), 0x48EEF0B07A8730C9L, 0x22F1A2ED0D547392L, 0x6142F1D32FD097C7L, 0x4A674D286AF0E2E1L, unchecked((long)0x80FD7CC9748CBED2L), 0x717E7067AF4F499AL, unchecked((long)0x938290A9ECD1DBB3L), unchecked((long)0x88E3B293344DD172L), 0x2734158C250FA3D6L}
		};
	}

}