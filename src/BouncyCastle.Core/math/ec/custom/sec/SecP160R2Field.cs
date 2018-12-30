using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{


	public class SecP160R2Field
	{
		// 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000, 0xFFFF58E6, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xE4BB4457, 0xFFFF58E5, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000A719, 0x00000002};
		private const uint P4 = 0xFFFFFFFF;
		private const uint PExt9 = 0xFFFFFFFF;
		private const uint PInv33 = 0x538D;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat160.add(x, y, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
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
				Nat.add33To(5, PInv33, z);
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
			ulong cc = Nat160.mul33Add(PInv33, xx, 5, xx, 0, z, 0);
			uint c = Nat160.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0 || c == 1;

			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			if ((x != 0 && Nat160.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
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
				Nat.sub33From(5, PInv33, z);
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
				Nat.add33To(5, PInv33, z);
			}
		}
	}

}