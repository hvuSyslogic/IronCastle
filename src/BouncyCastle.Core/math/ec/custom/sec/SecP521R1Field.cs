using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	

	public class SecP521R1Field
	{
		// 2^521 - 1
		internal static readonly uint[] P = new uint[]{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x1FF};
		private const int P16 = 0x1FF;

		public static void add(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat.add(16, x, y, z) + x[16] + y[16];
			if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
			{
				c += Nat.inc(16, z);
				c &= P16;
			}
			z[16] = c;
		}

		public static void addOne(uint[] x, uint[] z)
		{
			uint c = Nat.inc(16, x, z) + x[16];
			if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
			{
				c += Nat.inc(16, z);
				c &= P16;
			}
			z[16] = c;
		}

		public static uint[] fromBigInteger(BigInteger x)
		{
			uint[] z = Nat.fromBigInteger(521, x);
			if (Nat.eq(17, z, P))
			{
				Nat.zero(17, z);
			}
			return z;
		}

		public static void half(uint[] x, uint[] z)
		{
			uint x16 = x[16];
			uint c = Nat.shiftDownBit(16, x, x16, z);
			z[16] = (x16 >> 1) | ((c >> 23));
		}

		public static void multiply(uint[] x, uint[] y, uint[] z)
		{
			uint[] tt = Nat.create(33);
			implMultiply(x, y, tt);
			reduce(tt, z);
		}

		public static void negate(uint[] x, uint[] z)
		{
			if (Nat.isZero(17, x))
			{
				Nat.zero(17, z);
			}
			else
			{
				Nat.sub(17, P, x, z);
			}
		}

		public static void reduce(uint[] xx, uint[] z)
		{
	//        assert xx[32] >>> 18 == 0;

			uint xx32 = xx[32];
			uint c = (Nat.shiftDownBits(16, xx, 16, 9, xx32, z, 0) >> 23);
			c += (xx32 >> 9);
			c += Nat.addTo(16, xx, z);
			if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
			{
				c += Nat.inc(16, z);
				c &= P16;
			}
			z[16] = c;
		}

		public static void reduce23(uint[] z)
		{
			uint z16 = z[16];
			uint c = Nat.addWordTo(16, (z16 >> 9), z) + (z16 & P16);
			if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
			{
				c += Nat.inc(16, z);
				c &= P16;
			}
			z[16] = c;
		}

		public static void square(uint[] x, uint[] z)
		{
			uint[] tt = Nat.create(33);
			implSquare(x, tt);
			reduce(tt, z);
		}

		public static void squareN(uint[] x, int n, uint[] z)
		{
	//        assert n > 0;

			uint[] tt = Nat.create(33);
			implSquare(x, tt);
			reduce(tt, z);

			while (--n > 0)
			{
				implSquare(z, tt);
				reduce(tt, z);
			}
		}

		public static void subtract(uint[] x, uint[] y, uint[] z)
		{
			uint c = Nat.sub(16, x, y, z) + x[16] - y[16];
			if (c < 0)
			{
				c += Nat.dec(16, z);
				c &= P16;
			}
			z[16] = c;
		}

		public static void twice(uint[] x, uint[] z)
		{
			uint x16 = x[16];
			uint c = Nat.shiftUpBit(16, x, x16 << 23, z) | (x16 << 1);
			z[16] = c & P16;
		}

		protected internal static void implMultiply(uint[] x, uint[] y, uint[] zz)
		{
			Nat512.mul(x, y, zz);

			uint x16 = x[16], y16 = y[16];
			zz[32] = Nat.mul31BothAdd(16, x16, y, y16, x, zz, 16) + (x16 * y16);
		}

		protected internal static void implSquare(uint[] x, uint[] zz)
		{
			Nat512.square(x, zz);

			uint x16 = x[16];
			zz[32] = Nat.mulWordAddTo(16, x16 << 1, x, 0, zz, 16) + (x16 * x16);
		}
	}

}