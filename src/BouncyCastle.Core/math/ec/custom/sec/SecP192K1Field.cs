using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP192K1Field
	{
		// 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFEC3B02F, 0xFFFFDC6D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00002391, 0x00000002};
		private const uint P5 = unchecked(0xFFFFFFFF);
		private const uint PExt11 = unchecked(0xFFFFFFFF);
		private const uint PInv33 = 0x11C9;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat192.add(x, y, z);
			if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
			{
				Nat.add33To(6, PInv33, z);
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
				Nat.add33To(6, PInv33, z);
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
			ulong cc = Nat192.mul33Add(PInv33, xx, 6, xx, 0, z, 0);
			uint c = Nat192.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0L || c == 1L;

			if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
			{
				Nat.add33To(6, PInv33, z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			if ((x != 0 && Nat192.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[5] == P5 && Nat192.gte(z, P)))
			{
				Nat.add33To(6, PInv33, z);
			}
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat192.createExt();
			Nat192.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, uint n, uint[] z)
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
				Nat.sub33From(6, PInv33, z);
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
				Nat.add33To(6, PInv33, z);
			}
		}
	}

}