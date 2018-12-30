using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP384R1Field
	{
		// 2^384 - 2^128 - 2^96 + 2^32 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0x00000002};
		private const uint P11 = 0xFFFFFFFF;
		private const uint PExt23 = 0xFFFFFFFF;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat.add(12, x, y, z);
			if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(24, xx, yy, zz);
			if (c != 0 || (zz[23] == PExt23 && Nat.gte(24, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(24, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(12, x, z);
			if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
			{
				addPInvTo(z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat.fromBigInteger(384, x);
			if (z[11] == P11 && Nat.gte(12, z, P))
			{
				Nat.subFrom(12, P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(12, x, 0, z);
			}
			else
			{
				uint c = Nat.add(12, x, P, z);
				Nat.shiftDownBit(12, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat.create(24);
			Nat384.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat.isZero(12, x))
			{
				Nat.zero(12, z);
			}
			else
			{
				Nat.sub(12, P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
			ulong xx16 = xx[16], xx17 = xx[17], xx18 = xx[18], xx19 = xx[19];
			ulong xx20 = xx[20], xx21 = xx[21], xx22 = xx[22], xx23 = xx[23];

			const ulong n = 1;

			ulong t0 = (xx[12]) + xx20 - n;
			ulong t1 = (xx[13]) + xx22;
			ulong t2 = (xx[14]) + xx22 + xx23;
			ulong t3 = (xx[15]) + xx23;
			ulong t4 = xx17 + xx21;
			ulong t5 = xx21 - xx23;
			ulong t6 = xx22 - xx23;
			ulong t7 = t0 + t5;

			ulong cc = 0;
			cc += (xx[0]) + t7;
			z[0] = (uint)cc;
			cc >>= 32;
			cc += (xx[1]) + xx23 - t0 + t1;
			z[1] = (uint)cc;
			cc >>= 32;
			cc += (xx[2]) - xx21 - t1 + t2;
			z[2] = (uint)cc;
			cc >>= 32;
			cc += (xx[3]) - t2 + t3 + t7;
			z[3] = (uint)cc;
			cc >>= 32;
			cc += (xx[4]) + xx16 + xx21 + t1 - t3 + t7;
			z[4] = (uint)cc;
			cc >>= 32;
			cc += (xx[5]) - xx16 + t1 + t2 + t4;
			z[5] = (uint)cc;
			cc >>= 32;
			cc += (xx[6]) + xx18 - xx17 + t2 + t3;
			z[6] = (uint)cc;
			cc >>= 32;
			cc += (xx[7]) + xx16 + xx19 - xx18 + t3;
			z[7] = (uint)cc;
			cc >>= 32;
			cc += (xx[8]) + xx16 + xx17 + xx20 - xx19;
			z[8] = (uint)cc;
			cc >>= 32;
			cc += (xx[9]) + xx18 - xx20 + t4;
			z[9] = (uint)cc;
			cc >>= 32;
			cc += (xx[10]) + xx18 + xx19 - t5 + t6;
			z[10] = (uint)cc;
			cc >>= 32;
			cc += (xx[11]) + xx19 + xx20 - t6;
			z[11] = (uint)cc;
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
				ulong xx12 = x;
                
				cc += (z[0]) + xx12;
				z[0] = (uint)cc;
				cc >>= 32;
				cc += (z[1]) - xx12;
				z[1] = (uint)cc;
				cc >>= 32;
				if (cc != 0)
				{
					cc += (z[2]);
					z[2] = (uint)cc;
					cc >>= 32;
				}
				cc += (z[3]) + xx12;
				z[3] = (uint)cc;
				cc >>= 32;
				cc += (z[4]) + xx12;
				z[4] = (uint)cc;
				cc >>= 32;

	//            assert cc == 0 || cc == 1;
			}

			if ((cc != 0 && Nat.incAt(12, z, 5) != 0) || (z[11] == P11 && Nat.gte(12, z, P)))
			{
				addPInvTo(z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat.create(24);
			Nat384.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat.create(24);
			Nat384.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat384.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat.sub(12, x, y, z);
			if (c != 0)
			{
				subPInvFrom(z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(24, xx, yy, zz);
			if (c != 0)
			{
				if (Nat.subFrom(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.decAt(24, zz, PExtInv.Length);
				}
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(12, x, 0, z);
			if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
			{
				addPInvTo(z);
			}
		}

		private static void addPInvTo(uint[] z)
		{
			ulong c = (z[0]) + 1;
			z[0] = (uint)c;
			c >>= 32;
			c += (z[1]) - 1;
			z[1] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[2]);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3]) + 1;
			z[3] = (uint)c;
			c >>= 32;
			c += (z[4]) + 1;
			z[4] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.incAt(12, z, 5);
			}
		}

		private static void subPInvFrom(uint[] z)
		{
			ulong c = (z[0]) - 1;
			z[0] = (uint)c;
			c >>= 32;
			c += (z[1]) + 1;
			z[1] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				c += (z[2]);
				z[2] = (uint)c;
				c >>= 32;
			}
			c += (z[3]) - 1;
			z[3] = (uint)c;
			c >>= 32;
			c += (z[4]) - 1;
			z[4] = (uint)c;
			c >>= 32;
			if (c != 0)
			{
				Nat.decAt(12, z, 5);
			}
		}
	}

}