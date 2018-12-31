using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.crypto.modes.kgcm
{
	/// <summary>
	/// Utilities for the GF(2^m) field with corresponding extension polynomial:
	/// 
	/// GF (2^128) -> x^128 + x^7 + x^2 + x + 1
	/// 
	/// The representation is little-endian arrays of 64-bit words
	/// </summary>
	public class KGCMUtil_128
	{
		public const int SIZE = 2;

		public static void add(ulong[] x, ulong[] y, ulong[] z)
		{
			z[0] = x[0] ^ y[0];
			z[1] = x[1] ^ y[1];
		}

		public static void copy(ulong[] x, ulong[] z)
		{
			z[0] = x[0];
			z[1] = x[1];
		}

		public static bool equal(ulong[] x, ulong[] y)
		{
			ulong d = 0L;
			d |= x[0] ^ y[0];
			d |= x[1] ^ y[1];
			return d == 0UL;
		}

		public static void multiply(ulong[] x, ulong[] y, ulong[] z)
		{
			ulong x0 = x[0], x1 = x[1];
			ulong y0 = y[0], y1 = y[1];
			ulong z0 = 0, z1 = 0, z2 = 0;

			for (int j = 0; j < 64; ++j)
			{
				ulong m0 = -(x0 & 1L);
				x0 = (x0 >> 1);
				z0 ^= (y0 & m0);
				z1 ^= (y1 & m0);

				ulong m1 = -(x1 & 1L);
				x1 = (x1 >> 1);
				z1 ^= (y0 & m1);
				z2 ^= (y1 & m1);

				ulong c = y1 >> 63;
				y1 = (y1 << 1) | ((y0 >> 63));
				y0 = (y0 << 1) ^ (c & 0x87L);
			}

			z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
			z1 ^= ((z2 >> 63)) ^ ((z2 >> 62)) ^ ((z2 >> 57));

			z[0] = z0;
			z[1] = z1;
		}

		public static void multiplyX(ulong[] x, ulong[] z)
		{
			ulong x0 = x[0], x1 = x[1];
			ulong m = x1 >> 63;
			z[0] = (x0 << 1) ^ (m & 0x87L);
			z[1] = (x1 << 1) | ((x0 >> 63));
		}

		public static void multiplyX8(ulong[] x, ulong[] z)
		{
			ulong x0 = x[0], x1 = x[1];
			ulong c = (x1 >> 56);
			z[0] = (x0 << 8) ^ c ^ (c << 1) ^ (c << 2) ^ (c << 7);
			z[1] = (x1 << 8) | ((x0 >> 56));
		}

		public static void one(ulong[] z)
		{
			z[0] = 1;
			z[1] = 0;
		}

		public static void square(ulong[] x, ulong[] z)
		{
			ulong[] t = new ulong[4];
			Interleave.expand64To128(x[0], t, 0);
			Interleave.expand64To128(x[1], t, 2);

			ulong z0 = t[0], z1 = t[1], z2 = t[2], z3 = t[3];

			z1 ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
			z2 ^= ((z3 >> 63)) ^ ((z3 >> 62)) ^ ((z3 >> 57));

			z0 ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);
			z1 ^= ((z2 >> 63)) ^ ((z2 >> 62)) ^ ((z2 >> 57));

			z[0] = z0;
			z[1] = z1;
		}

		public static void x(ulong[] z)
		{
			z[0] = 2;
			z[1] = 0;
		}

		public static void zero(ulong[] z)
		{
			z[0] = 0;
			z[1] = 0;
		}
	}

}