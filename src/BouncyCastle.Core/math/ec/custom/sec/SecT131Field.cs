using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecT131Field
	{
		private static readonly ulong M03 = ulong.MaxValue >> 61;
		private static readonly ulong M44 = ulong.MaxValue >> 20;

		private static readonly ulong[] ROOT_Z = new ulong[] {0x26BC4D789AF13523L, 0x26BC4D789AF135E2L, 0x6L};

		public static void add(ulong[] x, ulong[] y, ulong[] z)
		{
			z[0] = x[0] ^ y[0];
			z[1] = x[1] ^ y[1];
			z[2] = x[2] ^ y[2];
		}

		public static void addExt(ulong[] xx, ulong[] yy, ulong[] zz)
		{
			zz[0] = xx[0] ^ yy[0];
			zz[1] = xx[1] ^ yy[1];
			zz[2] = xx[2] ^ yy[2];
			zz[3] = xx[3] ^ yy[3];
			zz[4] = xx[4] ^ yy[4];
		}

		public static void addOne(ulong[] x, ulong[] z)
		{
			z[0] = x[0] ^ 1L;
			z[1] = x[1];
			z[2] = x[2];
		}

		public static ulong[] fromBigInteger(BigInteger x)
		{
			ulong[] z = Nat192.fromBigInteger64(x);
			reduce61(z, 0);
			return z;
		}

		public static void invert(ulong[] x, ulong[] z)
		{
			if (Nat192.isZero64(x))
			{
				throw new IllegalStateException();
			}

			// Itoh-Tsujii inversion

			ulong[] t0 = Nat192.create64();
			ulong[] t1 = Nat192.create64();

			square(x, t0);
			multiply(t0, x, t0);
			squareN(t0, 2, t1);
			multiply(t1, t0, t1);
			squareN(t1, 4, t0);
			multiply(t0, t1, t0);
			squareN(t0, 8, t1);
			multiply(t1, t0, t1);
			squareN(t1, 16, t0);
			multiply(t0, t1, t0);
			squareN(t0, 32, t1);
			multiply(t1, t0, t1);
			square(t1, t1);
			multiply(t1, x, t1);
			squareN(t1, 65, t0);
			multiply(t0, t1, t0);
			square(t0, z);
		}

		public static void multiply(ulong[] x, ulong[] y, ulong[] z)
		{
			ulong[] tt = Nat192.createExt64();
			implMultiply(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(ulong[] x, ulong[] y, ulong[] zz)
		{
			ulong[] tt = Nat192.createExt64();
			implMultiply(x, y, tt);
			addExt(zz, tt, zz);
		}

		public static void reduce(ulong[] xx, ulong[] z)
		{
			ulong x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3], x4 = xx[4];

			x1 ^= (x4 << 61) ^ (x4 << 63);
			x2 ^= ((x4 >> 3)) ^ ((x4 >> 1)) ^ x4 ^ (x4 << 5);
			x3 ^= ((x4 >> 59));

			x0 ^= (x3 << 61) ^ (x3 << 63);
			x1 ^= ((x3 >> 3)) ^ ((x3 >> 1)) ^ x3 ^ (x3 << 5);
			x2 ^= ((x3 >> 59));

			ulong t = (x2 >> 3);
			z[0] = x0 ^ t ^ (t << 2) ^ (t << 3) ^ (t << 8);
			z[1] = x1 ^ ((t >> 56));
			z[2] = x2 & M03;
		}

		public static void reduce61(ulong[] z, int zOff)
		{
			ulong z2 = z[zOff + 2], t = (z2 >> 3);
			z[zOff] ^= t ^ (t << 2) ^ (t << 3) ^ (t << 8);
			z[zOff + 1] ^= ((t >> 56));
			z[zOff + 2] = z2 & M03;
		}

		public static void sqrt(ulong[] x, ulong[] z)
		{
			ulong[] odd = Nat192.create64();

			ulong u0, u1;
			u0 = Interleave.unshuffle(x[0]);
			u1 = Interleave.unshuffle(x[1]);
			ulong e0 = (u0 & 0x00000000FFFFFFFFUL) | (u1 << 32);
			odd[0] = ((u0 >> 32)) | (u1 & unchecked(0xFFFFFFFF00000000UL));

			u0 = Interleave.unshuffle(x[2]);
			ulong e1 = (u0 & 0x00000000FFFFFFFFUL);
			odd[1] = ((u0 >> 32));

			multiply(odd, ROOT_Z, z);

			z[0] ^= e0;
			z[1] ^= e1;
		}

		public static void square(ulong[] x, ulong[] z)
		{
			ulong[] tt = Nat.create64(5);
			implSquare(x, tt);
			reduce(tt, z);
		}

		public static void squareAddToExt(ulong[] x, ulong[] zz)
		{
			ulong[] tt = Nat.create64(5);
			implSquare(x, tt);
			addExt(zz, tt, zz);
		}

		public static void squareN(ulong[] x, int n, ulong[] z)
		{
	//        assert n > 0;

			ulong[] tt = Nat.create64(5);
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
			// Non-zero-trace bits: 0, 123, 129
			return (uint)(x[0] ^ ((x[1] >> 59)) ^ ((x[2] >> 1))) & 1;
		}

		protected internal static void implCompactExt(ulong[] zz)
		{
			ulong z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4], z5 = zz[5];
			zz[0] = z0 ^ (z1 << 44);
			zz[1] = (z1 >> 20) ^ (z2 << 24);
			zz[2] = (z2 >> 40) ^ (z3 << 4) ^ (z4 << 48);
			zz[3] = (z3 >> 60) ^ (z5 << 28) ^ (z4 >> 16);
			zz[4] = z5 >> 36;
			zz[5] = 0;
		}

		protected internal static void implMultiply(ulong[] x, ulong[] y, ulong[] zz)
		{
			/*
			 * "Five-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
			 */

			ulong f0 = x[0], f1 = x[1], f2 = x[2];
			f2 = (((f1 >> 24)) ^ (f2 << 40)) & M44;
			f1 = (((f0 >> 44)) ^ (f1 << 20)) & M44;
			f0 &= M44;

			ulong g0 = y[0], g1 = y[1], g2 = y[2];
			g2 = (((g1 >> 24)) ^ (g2 << 40)) & M44;
			g1 = (((g0 >> 44)) ^ (g1 << 20)) & M44;
			g0 &= M44;

			ulong[] H = new ulong[10];

			implMulw(f0, g0, H, 0); // H(0)       44/43 bits
			implMulw(f2, g2, H, 2); // H(INF)     44/41 bits

			ulong t0 = f0 ^ f1 ^ f2;
			ulong t1 = g0 ^ g1 ^ g2;

			implMulw(t0, t1, H, 4); // H(1)       44/43 bits

			ulong t2 = (f1 << 1) ^ (f2 << 2);
			ulong t3 = (g1 << 1) ^ (g2 << 2);

			implMulw(f0 ^ t2, g0 ^ t3, H, 6); // H(t)       44/45 bits
			implMulw(t0 ^ t2, t1 ^ t3, H, 8); // H(t + 1)   44/45 bits

			ulong t4 = H[6] ^ H[8];
			ulong t5 = H[7] ^ H[9];

		//    assert t5 >>> 44 == 0;

			// Calculate V
			ulong v0 = (t4 << 1) ^ H[6];
			ulong v1 = t4 ^ (t5 << 1) ^ H[7];
			ulong v2 = t5;

			// Calculate U
			ulong u0 = H[0];
			ulong u1 = H[1] ^ H[0] ^ H[4];
			ulong u2 = H[1] ^ H[5];

			// Calculate W
			ulong w0 = u0 ^ v0 ^ (H[2] << 4) ^ (H[2] << 1);
			ulong w1 = u1 ^ v1 ^ (H[3] << 4) ^ (H[3] << 1);
			ulong w2 = u2 ^ v2;

			// Propagate carries
			w1 ^= ((w0 >> 44));
			w0 &= M44;
			w2 ^= ((w1 >> 44));
			w1 &= M44;

	   //     assert (w0 & 1L) == 0;

			// Divide W by t

			w0 = ((w0 >> 1)) ^ ((w1 & 1L) << 43);
			w1 = ((w1 >> 1)) ^ ((w2 & 1L) << 43);
			w2 = ((w2 >> 1));

			// Divide W by (t + 1)

			w0 ^= (w0 << 1);
			w0 ^= (w0 << 2);
			w0 ^= (w0 << 4);
			w0 ^= (w0 << 8);
			w0 ^= (w0 << 16);
			w0 ^= (w0 << 32);

			w0 &= M44;
			w1 ^= ((w0 >> 43));

			w1 ^= (w1 << 1);
			w1 ^= (w1 << 2);
			w1 ^= (w1 << 4);
			w1 ^= (w1 << 8);
			w1 ^= (w1 << 16);
			w1 ^= (w1 << 32);

			w1 &= M44;
			w2 ^= ((w1 >> 43));

			w2 ^= (w2 << 1);
			w2 ^= (w2 << 2);
			w2 ^= (w2 << 4);
			w2 ^= (w2 << 8);
			w2 ^= (w2 << 16);
			w2 ^= (w2 << 32);

	  //      assert w2 >>> 42 == 0;

			zz[0] = u0;
			zz[1] = u1 ^ w0 ^ H[2];
			zz[2] = u2 ^ w1 ^ w0 ^ H[3];
			zz[3] = w2 ^ w1;
			zz[4] = w2 ^ H[2];
			zz[5] = H[3];

			implCompactExt(zz);
		}

		protected internal static void implMulw(ulong x, ulong y, ulong[] z, int zOff)
		{
	//        assert x >>> 45 == 0;
	//        assert y >>> 45 == 0;

			ulong[] u = new ulong[8];
	//      u[0] = 0;
			u[1] = y;
			u[2] = u[1] << 1;
			u[3] = u[2] ^ y;
			u[4] = u[2] << 1;
			u[5] = u[4] ^ y;
			u[6] = u[3] << 1;
			u[7] = u[6] ^ y;

			uint j = (uint)x;
			ulong g, h = 0, l = u[j & 7] ^ u[((j >> 3)) & 7] << 3 ^ u[((j >> 6)) & 7] << 6;
			int k = 33;
			do
			{
				j = (uint)((x >> k));
				g = u[j & 7] ^ u[((j >> 3)) & 7] << 3 ^ u[((j >> 6)) & 7] << 6 ^ u[((j >> 9)) & 7] << 9;
				l ^= (g << k);
				h ^= ((g >> -k));
			} while ((k -= 12) > 0);

	//        assert h >>> 25 == 0;

			z[zOff] = l & M44;
			z[zOff + 1] = ((l >> 44)) ^ (h << 20);
		}

		protected internal static void implSquare(ulong[] x, ulong[] zz)
		{
			Interleave.expand64To128(x[0], zz, 0);
			Interleave.expand64To128(x[1], zz, 2);

			zz[4] = Interleave.expand8To16((uint)x[2]);
		}
	}

}