using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class SecP224R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP224R1Curve.q;

		protected internal uint[] x;

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

		public SecP224R1FieldElement(uint[] x)
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
			uint[] z = Nat224.create();
			SecP224R1Field.add(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat224.create();
			SecP224R1Field.addOne(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat224.create();
			SecP224R1Field.subtract(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat224.create();
			SecP224R1Field.multiply(x, ((SecP224R1FieldElement)b).x, z);
			return new SecP224R1FieldElement(z);
		}
        
		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat224.create();
			Mod.invert(SecP224R1Field.P, ((SecP224R1FieldElement)b).x, z);
			SecP224R1Field.multiply(z, x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat224.create();
			SecP224R1Field.negate(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat224.create();
			SecP224R1Field.square(x, z);
			return new SecP224R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP224R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat224.create();
			Mod.invert(SecP224R1Field.P, x, z);
			return new SecP224R1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			uint[] c = this.x;
			if (Nat224.isZero(c) || Nat224.isOne(c))
			{
				return this;
			}

			uint[] nc = Nat224.create();
			SecP224R1Field.negate(c, nc);

			uint[] r = Mod.random(SecP224R1Field.P);
			uint[] t = Nat224.create();

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

		private static bool isSquare(uint[] x)
		{
			uint[] t1 = Nat224.create();
			uint[] t2 = Nat224.create();
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

		private static void RM(uint[] nc, uint[] d0, uint[] e0, uint[] d1, uint[] e1, uint[] f1, uint[] t)
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

		private static void RP(uint[] nc, uint[] d1, uint[] e1, uint[] f1, uint[] t)
		{
			Nat224.copy(nc, f1);

			uint[] d0 = Nat224.create();
			uint[] e0 = Nat224.create();

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

		private static void RS(uint[] d, uint[] e, uint[] f, uint[] t)
		{
			SecP224R1Field.multiply(e, d, e);
			SecP224R1Field.twice(e, e);
			SecP224R1Field.square(d, t);
			SecP224R1Field.add(f, t, d);
			SecP224R1Field.multiply(f, t, f);
			uint c = Nat.shiftUpBits(7, f, 2, 0);
			SecP224R1Field.reduce32(c, f);
		}

		private static bool trySqrt(uint[] nc, uint[] r, uint[] t)
		{
			uint[] d1 = Nat224.create();
			Nat224.copy(r, d1);
			uint[] e1 = Nat224.create();
			e1[0] = 1;
			uint[] f1 = Nat224.create();
			RP(nc, d1, e1, f1, t);

			uint[] d0 = Nat224.create();
			uint[] e0 = Nat224.create();

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