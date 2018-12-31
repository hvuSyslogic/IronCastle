using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	

	public class SecP160R1Field
	{
		// 2^160 - 2^31 - 1
		internal static readonly uint[] P = new uint[] {0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[] {0x00000001, 0x40000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFFFFFFFF, 0xBFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0x00000001};
		private const uint P4 = 0xFFFFFFFF;
		private const uint PExt9 = 0xFFFFFFFF;
		private const uint PInv = 0x80000001;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat160.add(x, y, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.addWordTo(5, PInv, z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(10, xx, yy, zz);
			if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(10, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(5, x, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.addWordTo(5, PInv, z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat160.fromBigInteger(x);
			if (z[4] == P4 && Nat160.gte(z, P))
			{
				Nat160.subFrom(P, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(5, x, 0, z);
			}
			else
			{
				uint c = Nat160.add(x, P, z);
				Nat.shiftDownBit(5, z, c);
			}
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat160.createExt();
			Nat160.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
		{
			uint c = Nat160.mulAddTo(x, y, zz);
			if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(10, zz, PExtInv.Length);
				}
			}
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat160.isZero(x))
			{
				Nat160.zero(z);
			}
			else
			{
				Nat160.sub(P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
			ulong x5 = xx[5] , x6 = xx[6], x7 = xx[7], x8 = xx[8], x9 = xx[9];

			ulong c = 0;
			c += (xx[0]) + x5 + (x5 << 31);
			z[0] = (uint)c;
			c = (c >> 32);
			c += (xx[1]) + x6 + (x6 << 31);
			z[1] = (uint)c;
			c = (c >> 32);
			c += (xx[2]) + x7 + (x7 << 31);
			z[2] = (uint)c;
			c = (c >> 32);
			c += (xx[3] ) + x8 + (x8 << 31);
			z[3] = (uint)c;
			c = (c >> 32);
			c += (xx[4]) + x9 + (x9 << 31);
			z[4] = (uint)c;
			c = (c >> 32);

	//        assert c >>> 32 == 0;

			reduce32((uint)c, z);
		}

		public static void reduce32(uint x, uint[] z)
		{
			if ((x != 0 && Nat160.mulWordsAdd(PInv, x, z, 0) != 0) || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.addWordTo(5, PInv, z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat160.createExt();
			Nat160.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat160.createExt();
			Nat160.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat160.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			int c = Nat160.sub(x, y, z);
			if (c != 0)
			{
				Nat.subWordFrom(5, PInv, z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			int c = Nat.sub(10, xx, yy, zz);
			if (c != 0)
			{
				if (Nat.subFrom(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.decAt(10, zz, PExtInv.Length);
				}
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(5, x, 0, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.addWordTo(5, PInv, z);
			}
		}
	}

}