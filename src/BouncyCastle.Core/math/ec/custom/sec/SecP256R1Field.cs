using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP256R1Field
	{
		// 2^256 - 2^224 + 2^192 + 2^96 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE, 0x00000002, 0xFFFFFFFE};
		private const uint P7 = 0xFFFFFFFF;
		private static readonly uint PExt15s1 = (0xFFFFFFFE >> 1);

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat256.add(x, y, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(16, xx, yy, zz);
			if (c != 0 || (((int)(zz[15] >> 1)) >= PExt15s1 && Nat.gte(16, zz, PExt)))
			{
				Nat.subFrom(16, PExt, zz);
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(8, x, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat256.fromBigInteger(x);
			if (z[7] == P7 && Nat256.gte(z, P))
			{
				Nat256.subFrom(P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(8, x, 0, z);
			}
			else
			{
				uint c = Nat256.add(x, P, z);
				Nat.shiftDownBit(8, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat256.createExt();
			Nat256.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
		{
			uint c = Nat256.mulAddTo(x, y, zz);
			if (c != 0 || (((int)(zz[15] >> 1)) >= PExt15s1 && Nat.gte(16, zz, PExt)))
			{
				Nat.subFrom(16, PExt, zz);
			}
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat256.isZero(x))
			{
				Nat256.zero(z);
			}
			else
			{
				Nat256.sub(P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
            ulong xx08 = xx[8], xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];
            ulong xx12 = xx[12], xx13 = xx[13], xx14 = xx[14], xx15 = xx[15];

			const ulong n = 6;

			xx08 -= n;

			ulong t0 = xx08 + xx09;
			ulong t1 = xx09 + xx10;
			ulong t2 = xx10 + xx11 - xx15;
			ulong t3 = xx11 + xx12;
			ulong t4 = xx12 + xx13;
			ulong t5 = xx13 + xx14;
			ulong t6 = xx14 + xx15;
			ulong t7 = t5 - t0;

            ulong cc = 0;
			cc += (xx[0]) - t3 - t7;
			z[0] = (uint)cc;
			cc >>= 32;
			cc += (xx[1]) + t1 - t4 - t6;
			z[1] = (uint)cc;
			cc >>= 32;
			cc += (xx[2]) + t2 - t5;
			z[2] = (uint)cc;
			cc >>= 32;
			cc += (xx[3]) + (t3 << 1) + t7 - t6;
			z[3] = (uint)cc;
			cc >>= 32;
			cc += (xx[4]) + (t4 << 1) + xx14 - t1;
			z[4] = (uint)cc;
			cc >>= 32;
			cc += (xx[5]) + (t5 << 1) - t2;
			z[5] = (uint)cc;
			cc >>= 32;
			cc += (xx[6]) + (t6 << 1) + t7;
			z[6] = (uint)cc;
			cc >>= 32;
			cc += (xx[7]) + (xx15 << 1) + xx08 - t2 - t4;
			z[7] = (uint)cc;
			cc >>= 32;
			cc += n;

	//        assert cc >= 0;

			reduce32((uint)cc, z);
		}

		public static void reduce32(uint x, uint[] z)
		{
			ulong cc = 0;

			if (x != 0)
			{
				ulong xx08 = x;

				cc += (z[0]) + xx08;
				z[0] = (uint)cc;
				cc >>= 32;
				if (cc != 0)
				{
					cc += (z[1]);
					z[1] = (uint)cc;
					cc >>= 32;
					cc += (z[2]);
					z[2] = (uint)cc;
					cc >>= 32;
				}
				cc += (z[3]) - xx08;
				z[3] = (uint)cc;
				cc >>= 32;
				if (cc != 0)
				{
					cc += (z[4]);
					z[4] = (uint)cc;
					cc >>= 32;
					cc += (z[5]);
					z[5] = (uint)cc;
					cc >>= 32;
				}
				cc += (z[6]) - xx08;
				z[6] = (uint)cc;
				cc >>= 32;
				cc += (z[7]) + xx08;
				z[7] = (uint)cc;
				cc >>= 32;

	//          assert cc == 0 || cc == 1;
			}

			if (cc != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat256.createExt();
			Nat256.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat256.createExt();
			Nat256.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat256.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat256.sub(x, y, z);
			if (c != 0)
			{
				subPInvFrom(z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(16, xx, yy, zz);
			if (c != 0)
			{
				Nat.addTo(16, PExt, zz);
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(8, x, 0, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		private static void addPInvTo(uint[] z)
		{
			ulong c = (z[0]) + 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1]);
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2]);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3]) - 1;
			z[3] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[4]);
				z[4] = (uint)c;
				c >>= 32;
				c += (z[5]);
				z[5] = (uint)c;
				c >>= 32;
			}
			c += (z[6]) - 1;
			z[6] = (uint)c;
			c >>= 32;
			c += (z[7]) + 1;
			z[7] = (uint)c;
	//        c >>= 32;
		}

		private static void subPInvFrom(uint[] z)
		{
			ulong c = (z[0]) - 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1]);
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2]);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3]) + 1;
			z[3] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[4]);
				z[4] = (uint)c;
				c >>= 32;
				c += (z[5]);
				z[5] = (uint)c;
				c >>= 32;
			}
			c += (z[6]) + 1;
			z[6] = (uint)c;
			c >>= 32;
			c += (z[7]) - 1;
			z[7] = (uint)c;
	//        c >>= 32;
		}
	}

}