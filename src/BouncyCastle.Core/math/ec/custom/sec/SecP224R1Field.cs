using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP224R1Field
	{
		// 2^224 - 2^96 + 1
		internal static readonly uint[] P = new uint[]{0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001};
		private const uint P6 = 0xFFFFFFFF;
		private const uint PExt13 = 0xFFFFFFFF;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat224.add(x, y, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(14, xx, yy, zz);
			if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(14, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(uint[] x,uint[] z)
		{
			uint c = Nat.inc(7, x, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat224.fromBigInteger(x);
			if (z[6] == P6 && Nat224.gte(z, P))
			{
				Nat224.subFrom(P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(7, x, 0, z);
			}
			else
			{
				uint c = Nat224.add(x, P, z);
				Nat.shiftDownBit(7, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat224.createExt();
			Nat224.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
		{
			uint c = Nat224.mulAddTo(x, y, zz);
			if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(14, zz, PExtInv.Length);
				}
			}
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat224.isZero(x))
			{
				Nat224.zero(z);
			}
			else
			{
				Nat224.sub(P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
			ulong xx10 = xx[10] , xx11 = xx[11] , xx12 = xx[12] , xx13 = xx[13] ;

			const ulong n = 1;

			ulong t0 = (xx[7] ) + xx11 - n;
			ulong t1 = (xx[8] ) + xx12;
			ulong t2 = (xx[9] ) + xx13;

			ulong cc = 0;
			cc += xx[0]  - t0;
			ulong z0 = cc ;
			cc >>= 32;
			cc += (xx[1]) - t1;
			z[1] = (uint)cc;
			cc >>= 32;
			cc += (xx[2]) - t2;
			z[2] = (uint)cc;
			cc >>= 32;
			cc += (xx[3]) + t0 - xx10;
			ulong z3 = cc ;
			cc >>= 32;
			cc += (xx[4]) + t1 - xx11;
			z[4] = (uint)cc;
			cc >>= 32;
			cc += (xx[5] ) + t2 - xx12;
			z[5] = (uint)cc;
			cc >>= 32;
			cc += (xx[6] ) + xx10 - xx13;
			z[6] = (uint)cc;
			cc >>= 32;
			cc += n;

	//        assert cc >= 0;

			z3 += cc;

			z0 -= cc;
			z[0] = (uint)z0;
			cc = z0 >> 32;
			if (cc != 0)
			{
				cc += (z[1] );
				z[1] = (uint)cc;
				cc >>= 32;
				cc += (z[2] );
				z[2] = (uint)cc;
				z3 += cc >> 32;
			}
			z[3] = (uint)z3;
			cc = z3 >> 32;

	//        assert cc == 0 || cc == 1;

			if ((cc != 0 && Nat.incAt(7, z, 4) != 0) || (z[6] == P6 && Nat224.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			ulong cc = 0;

			if (x != 0)
			{
				ulong xx07 = x ;

				cc += (z[0] ) - xx07;
				z[0] = (uint)cc;
				cc >>= 32;
				if (cc != 0)
				{
					cc += (z[1]);
					z[1] = (uint)cc;
					cc >>= 32;
					cc += (z[2] );
					z[2] = (uint)cc;
					cc >>= 32;
				}
				cc += (z[3] ) + xx07;
				z[3] = (uint)cc;
				cc >>= 32;

	//            assert cc == 0 || cc == 1;
			}

			if ((cc != 0 && Nat.incAt(7, z, 4) != 0) || (z[6] == P6 && Nat224.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat224.createExt();
			Nat224.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat224.createExt();
			Nat224.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat224.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat224.sub(x, y, z);
			if (c != 0)
			{
				subPInvFrom(z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(14, xx, yy, zz);
			if (c != 0)
			{
				if (Nat.subFrom(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.decAt(14, zz, PExtInv.Length);
				}
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(7, x, 0, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				addPInvTo(z);
			}
		}

		private static void addPInvTo(uint[] z)
		{
			ulong c = (z[0] ) - 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1] );
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2] );
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3]) + 1;
			z[3] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.incAt(7, z, 4);
			}
		}

		private static void subPInvFrom(uint[] z)
		{
			ulong c = (z[0] ) + 1;
			z[0] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[1] );
				z[1] = (uint)c;
				c >>= 32;
				c += (z[2]);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3] ) - 1;
			z[3] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.decAt(7, z, 4);
			}
		}
	}

}