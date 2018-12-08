using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Mod = org.bouncycastle.math.raw.Mod;
	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat224 = org.bouncycastle.math.raw.Nat224;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecP224R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP224R1Curve.q;

		protected internal int[] x;

		public SecP224R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP224R1FieldElement");
			}

			this.x = SecP224R1Field.fromBigInteger(x);
		}

		public SecP224R1FieldElement()
		{
			this.x = Nat224.create();
		}

		public SecP224R1FieldElement(int[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat224.isZero(x);
		}

		public override bool isOne()
		{
			return Nat224.isOne(x);
		}

		public override bool testBitZero()
		{
			return Nat224.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat224.toBigInteger(x);
		}

		public override string getFieldName()
		{
			return "SecP224R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			int[] z = Nat224.create();
			SecP224R1Field.add(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			int[] z = Nat224.create();
			SecP224R1Field.addOne(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			int[] z = Nat224.create();
			SecP224R1Field.subtract(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			int[] z = Nat224.create();
			SecP224R1Field.multiply(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			int[] z = Nat224.create();
			Mod.invert(SecP224R1Field.P, ((SecP224R1FieldElement)b).x, z);
			SecP224R1Field.multiply(z, x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			int[] z = Nat224.create();
			SecP224R1Field.negate(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			int[] z = Nat224.create();
			SecP224R1Field.square(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP224R1FieldElement(toBigInteger().modInverse(Q));
			int[] z = Nat224.create();
			Mod.invert(SecP224R1Field.P, x, z);
			return new SecP224R1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			int[] c = this.x;
			if (Nat224.isZero(c) || Nat224.isOne(c))
			{
				return this;
			}

			int[] nc = Nat224.create();
			SecP224R1Field.negate(c, nc);

			int[] r = Mod.random(SecP224R1Field.P);
			int[] t = Nat224.create();

			if (!isSquare(c))
			{
				return null;
			}

			while (!trySqrt(nc, r, t))
			{
				SecP224R1Field.addOne(r, r);
			}

			SecP224R1Field.square(t, r);

			return Nat224.eq(c, r) ? new SecP224R1FieldElement(t) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP224R1FieldElement))
			{
				return false;
			}

			SecP224R1FieldElement o = (SecP224R1FieldElement)other;
			return Nat224.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 7);
		}

		private static bool isSquare(int[] x)
		{
			int[] t1 = Nat224.create();
			int[] t2 = Nat224.create();
			Nat224.copy(x, t1);

			for (int i = 0; i < 7; ++i)
			{
				Nat224.copy(t1, t2);
				SecP224R1Field.squareN(t1, 1 << i, t1);
				SecP224R1Field.multiply(t1, t2, t1);
			}

			SecP224R1Field.squareN(t1, 95, t1);
			return Nat224.isOne(t1);
		}

		private static void RM(int[] nc, int[] d0, int[] e0, int[] d1, int[] e1, int[] f1, int[] t)
		{
			SecP224R1Field.multiply(e1, e0, t);
			SecP224R1Field.multiply(t, nc, t);
			SecP224R1Field.multiply(d1, d0, f1);
			SecP224R1Field.add(f1, t, f1);
			SecP224R1Field.multiply(d1, e0, t);
			Nat224.copy(f1, d1);
			SecP224R1Field.multiply(e1, d0, e1);
			SecP224R1Field.add(e1, t, e1);
			SecP224R1Field.square(e1, f1);
			SecP224R1Field.multiply(f1, nc, f1);
		}

		private static void RP(int[] nc, int[] d1, int[] e1, int[] f1, int[] t)
		{
			Nat224.copy(nc, f1);

			int[] d0 = Nat224.create();
			int[] e0 = Nat224.create();

			for (int i = 0; i < 7; ++i)
			{
				Nat224.copy(d1, d0);
				Nat224.copy(e1, e0);

				int j = 1 << i;
				while (--j >= 0)
				{
					RS(d1, e1, f1, t);
				}

				RM(nc, d0, e0, d1, e1, f1, t);
			}
		}

		private static void RS(int[] d, int[] e, int[] f, int[] t)
		{
			SecP224R1Field.multiply(e, d, e);
			SecP224R1Field.twice(e, e);
			SecP224R1Field.square(d, t);
			SecP224R1Field.add(f, t, d);
			SecP224R1Field.multiply(f, t, f);
			int c = Nat.shiftUpBits(7, f, 2, 0);
			SecP224R1Field.reduce32(c, f);
		}

		private static bool trySqrt(int[] nc, int[] r, int[] t)
		{
			int[] d1 = Nat224.create();
			Nat224.copy(r, d1);
			int[] e1 = Nat224.create();
			e1[0] = 1;
			int[] f1 = Nat224.create();
			RP(nc, d1, e1, f1, t);

			int[] d0 = Nat224.create();
			int[] e0 = Nat224.create();

			for (int k = 1; k < 96; ++k)
			{
				Nat224.copy(d1, d0);
				Nat224.copy(e1, e0);

				RS(d1, e1, f1, t);

				if (Nat224.isZero(d1))
				{
					Mod.invert(SecP224R1Field.P, e0, t);
					SecP224R1Field.multiply(t, d0, t);
					return true;
				}
			}

			return false;
		}
	}

}