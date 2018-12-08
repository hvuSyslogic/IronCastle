using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat224 = org.bouncycastle.math.raw.Nat224;

	public class SecP224K1Field
	{
		// 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
		internal static readonly int[] P = new int[]{unchecked((int)0xFFFFE56D), unchecked((int)0xFFFFFFFE), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF)};
		internal static readonly int[] PExt = new int[]{0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, unchecked((int)0xFFFFCADA), unchecked((int)0xFFFFFFFD), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF)};
		private static readonly int[] PExtInv = new int[]{unchecked((int)0xFD3DCF97), unchecked((int)0xFFFFCAD9), unchecked((int)0xFFFFFFFE), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), 0x00003525, 0x00000002};
		private const int P6 = unchecked((int)0xFFFFFFFF);
		private const int PExt13 = unchecked((int)0xFFFFFFFF);
		private const int PInv33 = 0x1A93;

		public static void add(int[] x, int[] y, int[] z)
		{
			int c = Nat224.add(x, y, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static void addExt(int[] xx, int[] yy, int[] zz)
		{
			int c = Nat.add(14, xx, yy, zz);
			if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(14, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(int[] x, int[] z)
		{
			int c = Nat.inc(7, x, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static int[] fromBigInteger(BigInteger x)
		{
			int[] z = Nat224.fromBigInteger(x);
			if (z[6] == P6 && Nat224.gte(z, P))
			{
				Nat.add33To(7, PInv33, z);
			}
			return z;
		}

		public static void half(int[] x, int[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(7, x, 0, z);
			}
			else
			{
				int c = Nat224.add(x, P, z);
				Nat.shiftDownBit(7, z, c);
			}
		}

		public static void multiply(int[] x, int[] y, int[] z)
		{
			int[] tt = Nat224.createExt();
			Nat224.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
		{
			int c = Nat224.mulAddTo(x, y, zz);
			if (c != 0 || (zz[13] == PExt13 && Nat.gte(14, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(14, zz, PExtInv.Length);
				}
			}
		}

		public static void negate(int[] x, int[] z)
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

		public static void reduce(int[] xx, int[] z)
		{
			long cc = Nat224.mul33Add(PInv33, xx, 7, xx, 0, z, 0);
			int c = Nat224.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0L || c == 1L;

			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static void reduce32(int x, int[] z)
		{
			if ((x != 0 && Nat224.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}

		public static void square(int[] x, int[] z)
		{
			int[] tt = Nat224.createExt();
			Nat224.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(int[] x, int n, int[] z)
		{
	//        assert n > 0;

			int[] tt = Nat224.createExt();
			Nat224.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat224.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(int[] x, int[] y, int[] z)
		{
			int c = Nat224.sub(x, y, z);
			if (c != 0)
			{
				Nat.sub33From(7, PInv33, z);
			}
		}

		public static void subtractExt(int[] xx, int[] yy, int[] zz)
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

		public static void twice(int[] x, int[] z)
		{
			int c = Nat.shiftUpBit(7, x, 0, z);
			if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
			{
				Nat.add33To(7, PInv33, z);
			}
		}
	}

}