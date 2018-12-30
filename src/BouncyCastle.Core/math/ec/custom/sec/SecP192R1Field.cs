using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP192R1Field
	{
		// 2^192 - 2^64 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000002};
		private const uint P5 = 0xFFFFFFFF;
		private const uint PExt11 = 0xFFFFFFFF;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat192.add(x, y, z);
			if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(12, xx, yy, zz);
			if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(12, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(6, x, z);
			if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat192.fromBigInteger(x);
			if (z[5] == P5 && Nat192.gte(z, P))
			{
				Nat192.subFrom(P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(6, x, 0, z);
			}
			else
			{
				uint c = Nat192.add(x, P, z);
				Nat.shiftDownBit(6, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat192.createExt();
			Nat192.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
		{
			uint c = Nat192.mulAddTo(x, y, zz);
			if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(12, zz, PExtInv.Length);
				}
			}
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat192.isZero(x))
			{
				Nat192.zero(z);
			}
			else
			{
				Nat192.sub(P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
			ulong xx06 = xx[6] , xx07 = xx[7], xx08 = xx[8];
            ulong xx09 = xx[9], xx10 = xx[10], xx11 = xx[11];

			ulong t0 = xx06 + xx10;
			ulong t1 = xx07 + xx11;

			ulong cc = 0;
			cc += (xx[0] ) + t0;
			uint z0 = (uint)cc;
			cc >>= 32;
			cc += (xx[1] ) + t1;
			z[1] = (uint)cc;
			cc >>= 32;

			t0 += xx08;
			t1 += xx09;

			cc += (xx[2] ) + t0;
			ulong z2 = cc ;
			cc >>= 32;
			cc += (xx[3] ) + t1;
			z[3] = (uint)cc;
			cc >>= 32;

			t0 -= xx06;
			t1 -= xx07;

			cc += (xx[4] ) + t0;
			z[4] = (uint)cc;
			cc >>= 32;
			cc += (xx[5] ) + t1;
			z[5] = (uint)cc;
			cc >>= 32;

			z2 += cc;

			cc += (z0 );
			z[0] = (uint)cc;
			cc >>= 32;
			if (cc != 0)
			{
				cc += (z[1]);
				z[1] = (uint)cc;
				z2 += cc >> 32;
			}
			z[2] = (uint)z2;
			cc = z2 >> 32;

	//      assert cc == 0 || cc == 1;

			if ((cc != 0 && Nat.incAt(6, z, 3) != 0) || (z[5] == P5 && Nat192.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			ulong cc = 0;

			if (x != 0)
			{
				ulong xx06 = x ;

				cc += (z[0] ) + xx06;
				z[0] = (uint)cc;
				cc >>= 32;
				if (cc != 0)
				{
					cc += (z[1]);
					z[1] = (uint)cc;
					cc >>= 32;
				}
				cc += (z[2]) + xx06;
				z[2] = (uint)cc;
				cc >>= 32;

	//            assert cc == 0 || cc == 1;
			}

			if ((cc != 0 && Nat.incAt(6, z, 3) != 0) || (z[5] == P5 && Nat192.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat192.createExt();
			Nat192.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat192.createExt();
			Nat192.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat192.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat192.sub(x, y, z);
			if (c != 0)
			{
				subPInvFrom(z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(12, xx, yy, zz);
			if (c != 0)
			{
				if (Nat.subFrom(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.decAt(12, zz, PExtInv.Length);
				}
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(6, x, 0, z);
			if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		private static void addPInvTo(uint[] z)
		{
			ulong c = (z[0] ) + 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1]);
				z[1] = (uint)c;
				c >>= 32;
			}
			c += (z[2] ) + 1;
			z[2] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.incAt(6, z, 3);
			}
		}

		private static void subPInvFrom(uint[] z)
		{
			ulong c = (z[0] ) - 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1] );
				z[1] = (uint)c;
				c >>= 32;
			}
			c += (z[2] ) - 1;
			z[2] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.decAt(6, z, 3);
			}
		}
	}

}