using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	

	public class SecT571Field
	{
		private static readonly ulong M59 = (unchecked((ulong)-1L) >> 5);

		private const ulong RM = unchecked(0xEF7BDEF7BDEF7BDEUL);

		private static readonly ulong[] ROOT_Z = new ulong[]{0x2BE1195F08CAFB99L, unchecked(0x95F08CAF84657C23L), unchecked(0xCAF84657C232BE11L), 0x657C232BE1195F08L, unchecked(0xF84657C2308CAF84L), 0x7C232BE1195F08CAL, unchecked(0xBE1195F08CAF8465L), 0x5F08CAF84657C232L, 0x784657C232BE119L};

		public static void add(ulong[] x, ulong[] y, ulong[] z)
		{
			for (int i = 0; i < 9; ++i)
			{
				z[i] = x[i] ^ y[i];
			}
		}

		private static void add(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
		{
			for (int i = 0; i < 9; ++i)
			{
				z[zOff + i] = x[xOff + i] ^ y[yOff + i];
			}
		}

		public static void addBothTo(ulong[] x, ulong[] y, ulong[] z)
		{
			for (int i = 0; i < 9; ++i)
			{
				z[i] ^= x[i] ^ y[i];
			}
		}

		private static void addBothTo(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
		{
			for (int i = 0; i < 9; ++i)
			{
				z[zOff + i] ^= x[xOff + i] ^ y[yOff + i];
			}
		}

		public static void addExt(ulong[] xx, ulong[] yy, ulong[] zz)
		{
			for (int i = 0; i < 18; ++i)
			{
				zz[i] = xx[i] ^ yy[i];
			}
		}

		public static void addOne(ulong[] x, ulong[] z)
		{
			z[0] = x[0] ^ 1L;
			for (int i = 1; i < 9; ++i)
			{
				z[i] = x[i];
			}
		}

		public static ulong[] fromBigInteger(BigInteger x)
		{
			ulong[] z = Nat576.fromBigInteger64(x);
			reduce5(z, 0);
			return z;
		}

		public static void invert(ulong[] x, ulong[] z)
		{
			if (Nat576.isZero64(x))
			{
				throw new IllegalStateException();
			}

			// Itoh-Tsujii inversion with bases { 2, 3, 5 }

			ulong[] t0 = Nat576.create64();
			ulong[] t1 = Nat576.create64();
			ulong[] t2 = Nat576.create64();

			square(x, t2);

			// 5 | 570
			square(t2, t0);
			square(t0, t1);
			multiply(t0, t1, t0);
			squareN(t0, 2, t1);
			multiply(t0, t1, t0);
			multiply(t0, t2, t0);

			// 3 | 114
			squareN(t0, 5, t1);
			multiply(t0, t1, t0);
			squareN(t1, 5, t1);
			multiply(t0, t1, t0);

			// 2 | 38
			squareN(t0, 15, t1);
			multiply(t0, t1, t2);

			// ! {2,3,5} | 19
			squareN(t2, 30, t0);
			squareN(t0, 30, t1);
			multiply(t0, t1, t0);

			// 3 | 9
			squareN(t0, 60, t1);
			multiply(t0, t1, t0);
			squareN(t1, 60, t1);
			multiply(t0, t1, t0);

			// 3 | 3
			squareN(t0, 180, t1);
			multiply(t0, t1, t0);
			squareN(t1, 180, t1);
			multiply(t0, t1, t0);

			multiply(t0, t2, z);
		}

		public static void multiply(ulong[] x, ulong[] y, ulong[] z)
		{
			ulong[] tt = Nat576.createExt64();
			implMultiply(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(ulong[] x, ulong[] y, ulong[] zz)
		{
			ulong[] tt = Nat576.createExt64();
			implMultiply(x, y, tt);
			addExt(zz, tt, zz);
		}

		public static void multiplyPrecomp(ulong[] x, ulong[] precomp, ulong[] z)
		{
			ulong[] tt = Nat576.createExt64();
			implMultiplyPrecomp(x, precomp, tt);
			reduce(tt, z);
		}

		public static void multiplyPrecompAddToExt(ulong[] x, ulong[] precomp, ulong[] zz)
		{
			ulong[] tt = Nat576.createExt64();
			implMultiplyPrecomp(x, precomp, tt);
			addExt(zz, tt, zz);
		}

		public static ulong[] precompMultiplicand(ulong[] x)
		{
			/*
			 * Precompute table of all 4-bit products of x (first section)
			 */
			int len = 9 << 4;
			ulong[] t = new ulong[len << 1];
			JavaSystem.arraycopy(x, 0, t, 9, 9);
	//        reduce5(T0, 9);
			int tOff = 0;
			for (int i = 7; i > 0; --i)
			{
				tOff += 18;
				Nat.shiftUpBit64(9, t, (int)((uint)tOff >> 1), 0L, t, tOff);
				reduce5(t, tOff);
				add(t, 9, t, tOff, t, tOff + 9);
			}

			/*
			 * Second section with all 4-bit products of B shifted 4 bits
			 */
			Nat.shiftUpBits64(len, t, 0, 4, 0L, t, len);

			return t;
		}

		public static void reduce(ulong[] xx, ulong[] z)
		{
			ulong xx09 = xx[9];
			ulong u = xx[17], v = xx09;

			xx09 = v ^ u >> 59 ^ u >> 57 ^ u >> 54 ^ u >> 49;
			v = xx[8] ^ (u << 5) ^ (u << 7) ^ (u << 10) ^ (u << 15);

			for (int i = 16; i >= 10; --i)
			{
				u = xx[i];
				z[i - 8] = v ^ u >> 59 ^ u >> 57 ^ u >> 54 ^ u >> 49;
				v = xx[i - 9] ^ (u << 5) ^ (u << 7) ^ (u << 10) ^ (u << 15);
			}

			u = xx09;
			z[1] = v ^ u >> 59 ^ u >> 57 ^ u >> 54 ^ u >> 49;
			v = xx[0] ^ (u << 5) ^ (u << 7) ^ (u << 10) ^ (u << 15);

			ulong x08 = z[8];
			ulong t = x08 >> 59;
			z[0] = v ^ t ^ (t << 2) ^ (t << 5) ^ (t << 10);
			z[8] = x08 & M59;
		}

		public static void reduce5(ulong[] z, int zOff)
		{
			ulong z8 = z[zOff + 8], t = z8 >> 59;
			z[zOff] ^= t ^ (t << 2) ^ (t << 5) ^ (t << 10);
			z[zOff + 8] = z8 & M59;
		}

		public static void sqrt(ulong[] x, ulong[] z)
		{
			ulong[] evn = Nat576.create64(), odd = Nat576.create64();

			int pos = 0;
			for (int i = 0; i < 4; ++i)
			{
				ulong u0 = Interleave.unshuffle(x[pos++]);
				ulong u1 = Interleave.unshuffle(x[pos++]);
				evn[i] = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
				odd[i] = u0 >> 32 | (u1 & unchecked(0xFFFFFFFF00000000L));
			}
			{
				ulong u0 = Interleave.unshuffle(x[pos]);
				evn[4] = (u0 & 0x00000000FFFFFFFFL);
				odd[4] = u0 >> 32;
			}

			multiply(odd, ROOT_Z, z);
			add(z, evn, z);
		}

		public static void square(ulong[] x, ulong[] z)
		{
			ulong[] tt = Nat576.createExt64();
			implSquare(x, tt);
			reduce(tt, z);
		}

		public static void squareAddToExt(ulong[] x, ulong[] zz)
		{
			ulong[] tt = Nat576.createExt64();
			implSquare(x, tt);
			addExt(zz, tt, zz);
		}

		public static void squareN(ulong[] x, int n, ulong[] z)
		{
	//        assert n > 0;

			ulong[] tt = Nat576.createExt64();
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
			// Non-zero-trace bits: 0, 561, 569
			return (uint)(x[0] ^ x[8] >> 49 ^ x[8] >> 57) & 1;
		}

		protected internal static void implMultiply(ulong[] x, ulong[] y, ulong[] zz)
		{
	//        for (int i = 0; i < 9; ++i)
	//        {
	//            implMulwAcc(x, y[i], zz, i);
	//        }

			ulong[] precomp = precompMultiplicand(y);

			implMultiplyPrecomp(x, precomp, zz);
		}

		protected internal static void implMultiplyPrecomp(ulong[] x, ulong[] precomp, ulong[] zz)
		{
			int MASK = 0xF;

			/*
			 * Lopez-Dahab algorithm
			 */

			for (int k = 56; k >= 0; k -= 8)
			{
				for (int j = 1; j < 9; j += 2)
				{
					int aVal = (int)(x[j] >> k);
					int u = aVal & MASK;
					int v = ((int)((uint)aVal >> 4)) & MASK;
					addBothTo(precomp, 9 * u, precomp, 9 * (v + 16), zz, j - 1);
				}
				Nat.shiftUpBits64(16, zz, 0, 8, 0L);
			}

			for (int k = 56; k >= 0; k -= 8)
			{
				for (int j = 0; j < 9; j += 2)
				{
					int aVal = (int)(x[j] >> k);
					int u = aVal & MASK;
					int v = ((int)((uint)aVal >> 4)) & MASK;
					addBothTo(precomp, 9 * u, precomp, 9 * (v + 16), zz, j);
				}
				if (k > 0)
				{
					Nat.shiftUpBits64(18, zz, 0, 8, 0L);
				}
			}
		}

		protected internal static void implMulwAcc(ulong[] xs, ulong y, ulong[] z, int zOff)
		{
			ulong[] u = new ulong[32];
	//      u[0] = 0;
			u[1] = y;
			for (int i = 2; i < 32; i += 2)
			{
				u[i] = u[(int)((uint)i >> 1)] << 1;
				u[i + 1] = u[i] ^ y;
			}

			ulong l = 0;
			for (int i = 0; i < 9; ++i)
			{
				ulong x = xs[i];

				int j = (int)x;

				l ^= u[j & 31];

				ulong g, h = 0;
				int k = 60;
				do
				{
					j = (int)(x >> k);
					g = u[j & 31];
					l ^= (g << k);
					h ^= g >> -k;
				} while ((k -= 5) > 0);

				for (int p = 0; p < 4; ++p)
				{
					x = (x & RM) >> 1;
					h ^= x & ((y << p) >> 63);
				}

				z[zOff + i] ^= l;

				l = h;
			}
			z[zOff + 9] ^= l;
		}

		protected internal static void implSquare(ulong[] x, ulong[] zz)
		{
			for (int i = 0; i < 9; ++i)
			{
				Interleave.expand64To128(x[i], zz, i << 1);
			}
		}
	}

}