using System.Diagnostics;
using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP128R1Field
	{
		private const long M = 0xFFFFFFFFL;

		// 2^128 - 2^97 - 1
		internal static readonly uint[] P = new uint[] {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD};
		internal static readonly uint[] PExt = new uint[] {0x00000001, 0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFC};
		private static readonly uint[] PExtInv = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB, 0x00000001, 0x00000000, 0xFFFFFFFC, 0x00000003};
        private const uint P3s1 = 0xFFFFFFFD;
        private const uint PExt7s1 = 0xFFFFFFFC;

        public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat128.add(x, y, z);
			if (c != 0 || (z[3] >> 1) >= P3s1 && Nat128.gte(z, P))
			{
				addPInvTo(z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat256.add(xx, yy, zz);
			if (c != 0 || ((zz[7] >> 1) >= PExt7s1 && Nat256.gte(zz, PExt)))
			{
				Nat.addTo(PExtInv.Length, PExtInv, zz);
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(4, x, z);
			if (c != 0 || ((z[3] >> 1) >= P3s1 && Nat128.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat128.fromBigInteger(x);
			if ((z[3] >> 1) >= P3s1 && Nat128.gte(z, P))
			{
				Nat128.subFrom(P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(4, x, 0, z);
			}
			else
			{
				uint c = Nat128.add(x, P, z);
				Nat.shiftDownBit(4, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat128.createExt();
			Nat128.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
		{
			uint c = Nat128.mulAddTo(x, y, zz);
			if (c != 0 || ((zz[7] >> 1) >= PExt7s1 && Nat256.gte(zz, PExt)))
			{
				Nat.addTo(PExtInv.Length, PExtInv, zz);
			}
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat128.isZero(x))
			{
				Nat128.zero(z);
			}
			else
			{
				Nat128.sub(P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
			long x0 = xx[0] & M, x1 = xx[1] & M, x2 = xx[2] & M, x3 = xx[3] & M;
			long x4 = xx[4] & M, x5 = xx[5] & M, x6 = xx[6] & M, x7 = xx[7] & M;

			x3 += x7;
			x6 += (x7 << 1);
			x2 += x6;
			x5 += (x6 << 1);
			x1 += x5;
			x4 += (x5 << 1);
			x0 += x4;
			x3 += (x4 << 1);

			z[0] = (uint)x0;
			x1 += (x0 >> 32);
			z[1] = (uint)x1;
			x2 += x1 >> 32;
			z[2] = (uint)x2;
			x3 += x2 >> 32;
			z[3] = (uint)x3;

			reduce32((uint)(x3 >> 32), z);
		}

		public static void reduce32(uint x, uint[] z)
		{
			while (x != 0)
			{
				long c, x4 = x & M;

				c = (z[0] & M) + x4;
				z[0] = (uint)c;
				c >>= 32;
				if (c != 0)
				{
					c += (z[1] & M);
					z[1] = (uint)c;
					c >>= 32;
					c += (z[2] & M);
					z[2] = (uint)c;
					c >>= 32;
				}
				c += (z[3] & M) + (x4 << 1);
				z[3] = (uint)c;
				c >>= 32;

                Debug.Assert(c >= 0 && c <= 2);
                
                x = (uint)c;
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat128.createExt();
			Nat128.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat128.createExt();
			Nat128.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat128.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat128.sub(x, y, z);
			if (c != 0)
			{
				subPInvFrom(z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(10, xx, yy, zz);
			if (c != 0)
			{
				Nat.subFrom(PExtInv.Length, PExtInv, zz);
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(4, x, 0, z);
			if (c != 0 || (((z[3] >> 1)) >= P3s1 && Nat128.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		private static void addPInvTo(uint[] z)
		{
			long c = (z[0] & M) + 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1] & M);
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2] & M);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3] & M) + 2;
			z[3] = (uint)c;
		}

		private static void subPInvFrom(uint[] z)
		{
			long c = (z[0] & M) - 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1] & M);
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2] & M);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3] & M) - 2;
			z[3] = (uint)c;
		}
	}

}