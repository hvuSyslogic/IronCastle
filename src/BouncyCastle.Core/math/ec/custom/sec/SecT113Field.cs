using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecT113Field
	{
		private static readonly ulong M49 = ulong.MaxValue >> 15;
		private static readonly ulong M57 = ulong.MaxValue >> 7;

		public static void add(ulong[] x, ulong[] y, ulong[] z)
		{
			z[0] = x[0] ^ y[0];
			z[1] = x[1] ^ y[1];
		}

		public static void addExt(ulong[] xx, ulong[] yy, ulong[] zz)
		{
			zz[0] = xx[0] ^ yy[0];
			zz[1] = xx[1] ^ yy[1];
			zz[2] = xx[2] ^ yy[2];
			zz[3] = xx[3] ^ yy[3];
		}

		public static void addOne(ulong[] x, ulong[] z)
		{
			z[0] = x[0] ^ 1L;
			z[1] = x[1];
		}

		public static ulong[] fromBigInteger(BigInteger x)
		{
			ulong[] z = Nat128.fromBigInteger64(x);
			reduce15(z, 0);
			return z;
		}

		public static void invert(ulong[] x, ulong[] z)
		{
			if (Nat128.isZero64(x))
			{
				throw new IllegalStateException();
			}

			// Itoh-Tsujii inversion

			ulong[] t0 = Nat128.create64();
			ulong[] t1 = Nat128.create64();

			square(x, t0);
			multiply(t0, x, t0);
			square(t0, t0);
			multiply(t0, x, t0);
			squareN(t0, 3, t1);
			multiply(t1, t0, t1);
			square(t1, t1);
			multiply(t1, x, t1);
			squareN(t1, 7, t0);
			multiply(t0, t1, t0);
			squareN(t0, 14, t1);
			multiply(t1, t0, t1);
			squareN(t1, 28, t0);
			multiply(t0, t1, t0);
			squareN(t0, 56, t1);
			multiply(t1, t0, t1);
			square(t1, z);
		}

		public static void multiply(ulong[] x, ulong[] y, ulong[] z)
		{
			ulong[] tt = Nat128.createExt64();
			implMultiply(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(ulong[] x, ulong[] y, ulong[] zz)
		{
			ulong[] tt = Nat128.createExt64();
			implMultiply(x, y, tt);
			addExt(zz, tt, zz);
		}

		public static void reduce(ulong[] xx, ulong[] z)
		{
			ulong x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3];

			x1 ^= (x3 << 15) ^ (x3 << 24);
			x2 ^= ((x3 >> 49)) ^ ((x3 >> 40));

			x0 ^= (x2 << 15) ^ (x2 << 24);
			x1 ^= ((x2 >> 49)) ^ ((x2 >> 40));

			ulong t = (x1 >> 49);
			z[0] = x0 ^ t ^ (t << 9);
			z[1] = x1 & M49;
		}

		public static void reduce15(ulong[] z, int zOff)
		{
			ulong z1 = z[zOff + 1], t = (z1 >> 49);
			z[zOff] ^= t ^ (t << 9);
			z[zOff + 1] = z1 & M49;
		}

		public static void sqrt(ulong[] x, ulong[] z)
		{
			ulong u0 = Interleave.unshuffle(x[0]), u1 = Interleave.unshuffle(x[1]);
			ulong e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
			ulong c0 = ((u0 >> 32)) | (u1 & unchecked(0xFFFFFFFF00000000UL));

			z[0] = e0 ^ (c0 << 57) ^ (c0 << 5);
			z[1] = ((c0 >> 7)) ^ ((c0 >> 59));
		}

		public static void square(ulong[] x, ulong[] z)
		{
			ulong[] tt = Nat128.createExt64();
			implSquare(x, tt);
			reduce(tt, z);
		}

		public static void squareAddToExt(ulong[] x, ulong[] zz)
		{
			ulong[] tt = Nat128.createExt64();
			implSquare(x, tt);
			addExt(zz, tt, zz);
		}

		public static void squareN(ulong[] x, int n, ulong[] z)
		{
	//        assert n > 0;

			ulong[] tt = Nat128.createExt64();
			implSquare(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				implSquare(z, tt);
				reduce(tt, z);
			}
		}

		public static uint trace(ulong[] x)
		{
			// Non-zero-trace bits: 0
			return (uint)(x[0]) & 1;
		}

		protected internal static void implMultiply(ulong[] x, ulong[] y, ulong[] zz)
		{
			/*
			 * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
			 */

			ulong f0 = x[0], f1 = x[1];
			f1 = (((f0 >> 57)) ^ (f1 << 7)) & M57;
			f0 &= M57;

			ulong g0 = y[0], g1 = y[1];
			g1 = (((g0 >> 57)) ^ (g1 << 7)) & M57;
			g0 &= M57;

			ulong[] H = new ulong[6];

			implMulw(f0, g0, H, 0); // H(0)       57/56 bits
			implMulw(f1, g1, H, 2); // H(INF)     57/54 bits
			implMulw(f0 ^ f1, g0 ^ g1, H, 4); // H(1)       57/56 bits

			ulong r = H[1] ^ H[2];
			ulong z0 = H[0], z3 = H[3], z1 = H[4] ^ z0 ^ r, z2 = H[5] ^ z3 ^ r;

			zz[0] = z0 ^ (z1 << 57);
			zz[1] = ((z1 >> 7)) ^ (z2 << 50);
			zz[2] = ((z2 >> 14)) ^ (z3 << 43);
			zz[3] = ((z3 >> 21));
		}

		protected internal static void implMulw(ulong x, ulong y, ulong[] z, int zOff)
		{
	//        assert x >>> 57 == 0;
	//        assert y >>> 57 == 0;

			ulong[] u = new ulong[8];
	//      u[0] = 0;
			u[1] = y;
			u[2] = u[1] << 1;
			u[3] = u[2] ^ y;
			u[4] = u[2] << 1;
			u[5] = u[4] ^ y;
			u[6] = u[3] << 1;
			u[7] = u[6] ^ y;

			int j = (int)x;
			ulong g, h = 0, l = u[j & 7];
			int k = 48;
			do
			{
				j = (int)((x >> k));
				g = u[j & 7] ^ u[((j >> 3)) & 7] << 3 ^ u[((j >> 6)) & 7] << 6;
				l ^= (g << k);
				h ^= ((g >> -k));
			} while ((k -= 9) > 0);

			h ^= (((x & 0x0100804020100800UL) & ((y << 7) >> 63)) >> 8);

	//        assert h >>> 49 == 0;

			z[zOff] = l & M57;
			z[zOff + 1] = ((l >> 57)) ^ (h << 7);
		}

		protected internal static void implSquare(ulong[] x, ulong[] zz)
		{
			Interleave.expand64To128(x[0], zz, 0);
			Interleave.expand64To128(x[1], zz, 2);
		}
	}

}