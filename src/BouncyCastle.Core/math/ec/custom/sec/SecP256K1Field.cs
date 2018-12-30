using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP256K1Field
	{
		// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		internal static readonly uint[] PExt = new uint[]{0x000E90A1, 0x000007A2, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
		private static readonly uint[] PExtInv = new uint[]{0xFFF16F5F, 0xFFFFF85D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000007A1, 0x00000002};
		private const uint P7 = 0xFFFFFFFF;
		private const uint PExt15 = 0xFFFFFFFF;
		private const uint PInv33 = 0x3D1;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			var c = Nat256.add(x, y, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				Nat.add33To(8, PInv33, z);
			}
		}

		public static void addExt(uint[] xx, uint[] yy, uint[] zz)
		{
			uint c = Nat.add(16, xx, yy, zz);
			if (c != 0 || (zz[15] == PExt15 && Nat.gte(16, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(16, zz, PExtInv.Length);
				}
			}
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(8, x, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				Nat.add33To(8, PInv33, z);
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
			if (c != 0 || (zz[15] == PExt15 && Nat.gte(16, zz, PExt)))
			{
				if (Nat.addTo(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.incAt(16, zz, PExtInv.Length);
				}
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
			ulong cc = Nat256.mul33Add(PInv33, xx, 8, xx, 0, z, 0);
			uint c = Nat256.mul33DWordAdd(PInv33, cc, z, 0);

			// assert c == 0L || c == 1L;

			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				Nat.add33To(8, PInv33, z);
			}
		}

		public static void reduce32(uint x, uint[] z)
		{
			if ((x != 0 && Nat256.mul33WordAdd(PInv33, x, z, 0) != 0) || (z[7] == P7 && Nat256.gte(z, P)))
			{
				Nat.add33To(8, PInv33, z);
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
			var c = Nat256.sub(x, y, z);
			if (c != 0)
			{
				Nat.sub33From(8, PInv33, z);
			}
		}

		public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
		{
			var c = Nat.sub(16, xx, yy, zz);
			if (c != 0)
			{
				if (Nat.subFrom(PExtInv.Length, PExtInv, zz) != 0)
				{
					Nat.decAt(16, zz, PExtInv.Length);
				}
			}
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint c = Nat.shiftUpBit(8, x, 0, z);
			if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
			{
				Nat.add33To(8, PInv33, z);
			}
		}
	}

}