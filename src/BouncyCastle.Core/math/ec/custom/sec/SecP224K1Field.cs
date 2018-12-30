using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP224K1Field
	{
		// 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFCADA, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFD3DCF97, 0xFFFFCAD9, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00003525, 0x00000002};
		private const uint P6 = 0xFFFFFFFF;
		private const uint PExt13 = 0xFFFFFFFF;
		private const uint PInv33 = 0x1A93;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat224.add(x, y, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
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

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(7, x, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat224.fromBigInteger(x);
			if (z[6] == P6 && Nat224.gte(z, P))
			{
				Nat.add33To(7, PInv33, z);
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
			ulong cc = Nat224.mul33Add(PInv33, xx, 7, xx, 0, z, 0);
			uint c = Nat224.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0L || c == 1L;

			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			if ((x != 0 && Nat224.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat224.createExt();
			Nat224.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, uint n, uint[] z)
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
				Nat.sub33From(7, PInv33, z);
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
				Nat.add33To(7, PInv33, z);
			}
		}
	}

}