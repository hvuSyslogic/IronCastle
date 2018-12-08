using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat160 = org.bouncycastle.math.raw.Nat160;

	public class SecP160R2Field
	{
		// 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
		internal static readonly int[] P = new int[]{unchecked((int)0xFFFFAC73), unchecked((int)0xFFFFFFFE), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF)};
		internal static readonly int[] PExt = new int[]{0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000, unchecked((int)0xFFFF58E6), unchecked((int)0xFFFFFFFD), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF)};
		private static readonly int[] PExtInv = new int[]{unchecked((int)0xE4BB4457), unchecked((int)0xFFFF58E5), unchecked((int)0xFFFFFFFE), unchecked((int)0xFFFFFFFF), unchecked((int)0xFFFFFFFF), 0x0000A719, 0x00000002};
		private const int P4 = unchecked((int)0xFFFFFFFF);
		private const int PExt9 = unchecked((int)0xFFFFFFFF);
		private const int PInv33 = 0x538D;

		public static void add(int[] x, int[] y, int[] z)
		{
			int c = Nat160.add(x, y, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}

		public static void addExt(int[] xx, int[] yy, int[] zz)
		{
			int c = Nat.add(10, xx, yy, zz);
			if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(10, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(int[] x, int[] z)
		{
			int c = Nat.inc(5, x, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}

		public static int[] fromBigInteger(BigInteger x)
		{
			int[] z = Nat160.fromBigInteger(x);
			if (z[4] == P4 && Nat160.gte(z, P))
			{
				Nat160.subFrom(P, z);
			}
			return z;
		}

		public static void half(int[] x, int[] z)
		{
			if ((x[0] & 1) == 0)
			{
				Nat.shiftDownBit(5, x, 0, z);
			}
			else
			{
				int c = Nat160.add(x, P, z);
				Nat.shiftDownBit(5, z, c);
			}
		}

		public static void multiply(int[] x, int[] y, int[] z)
		{
			int[] tt = Nat160.createExt();
			Nat160.mul(x, y, tt);
			reduce(tt, z);
		}

		public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
		{
			int c = Nat160.mulAddTo(x, y, zz);
			if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(10, zz, PExtInv.Length);
				}
			}
		}

		public static void negate(int[] x, int[] z)
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

		public static void reduce(int[] xx, int[] z)
		{
			long cc = Nat160.mul33Add(PInv33, xx, 5, xx, 0, z, 0);
			int c = Nat160.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0 || c == 1;

			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}

		public static void reduce32(int x, int[] z)
		{
			if ((x != 0 && Nat160.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}

		public static void square(int[] x, int[] z)
		{
			int[] tt = Nat160.createExt();
			Nat160.square(x, tt);
			reduce(tt, z);
		}

		public static void squareN(int[] x, int n, int[] z)
		{
	//        assert n > 0;

			int[] tt = Nat160.createExt();
			Nat160.square(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				Nat160.square(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(int[] x, int[] y, int[] z)
		{
			int c = Nat160.sub(x, y, z);
			if (c != 0)
			{
				Nat.sub33From(5, PInv33, z);
			}
		}

		public static void subtractExt(int[] xx, int[] yy, int[] zz)
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

		public static void twice(int[] x, int[] z)
		{
			int c = Nat.shiftUpBit(5, x, 0, z);
			if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
			{
				Nat.add33To(5, PInv33, z);
			}
		}
	}

}