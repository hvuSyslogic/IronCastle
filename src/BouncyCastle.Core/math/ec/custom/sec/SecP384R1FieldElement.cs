using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	
	public class SecP384R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP384R1Curve.q;

		protected internal uint[] x;

		public SecP384R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP384R1FieldElement");
			}

			this.x = SecP384R1Field.fromBigInteger(x);
		}

		public SecP384R1FieldElement()
		{
			this.x = Nat.create(12);
		}

		public SecP384R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat.isZero(12, x);
		}

		public override bool isOne()
		{
			return Nat.isOne(12, x);
		}

		public override bool testBitZero()
		{
			return Nat.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat.toBigInteger(12, x);
		}

		public override string getFieldName()
		{
			return "SecP384R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.add(x, ((SecP384R1FieldElement)b).x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.addOne(x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.subtract(x, ((SecP384R1FieldElement)b).x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.multiply(x, ((SecP384R1FieldElement)b).x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat.create(12);
			Mod.invert(SecP384R1Field.P, ((SecP384R1FieldElement)b).x, z);
			SecP384R1Field.multiply(z, x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.negate(x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat.create(12);
			SecP384R1Field.square(x, z);
			return new SecP384R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP384R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat.create(12);
			Mod.invert(SecP384R1Field.P, x, z);
			return new SecP384R1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			// Raise this element to the exponent 2^382 - 2^126 - 2^94 + 2^30

			uint[] x1 = this.x;
			if (Nat.isZero(12, x1) || Nat.isOne(12, x1))
			{
				return this;
			}

			uint[] t1 = Nat.create(12);
            uint[] t2 = Nat.create(12);
            uint[] t3 = Nat.create(12);
            uint[] t4 = Nat.create(12);

			SecP384R1Field.square(x1, t1);
			SecP384R1Field.multiply(t1, x1, t1);

			SecP384R1Field.squareN(t1, 2, t2);
			SecP384R1Field.multiply(t2, t1, t2);

			SecP384R1Field.square(t2, t2);
			SecP384R1Field.multiply(t2, x1, t2);

			SecP384R1Field.squareN(t2, 5, t3);
			SecP384R1Field.multiply(t3, t2, t3);

			SecP384R1Field.squareN(t3, 5, t4);
			SecP384R1Field.multiply(t4, t2, t4);

			SecP384R1Field.squareN(t4, 15, t2);
			SecP384R1Field.multiply(t2, t4, t2);

			SecP384R1Field.squareN(t2, 2, t3);
			SecP384R1Field.multiply(t1, t3, t1);

			SecP384R1Field.squareN(t3, 28, t3);
			SecP384R1Field.multiply(t2, t3, t2);

			SecP384R1Field.squareN(t2, 60, t3);
			SecP384R1Field.multiply(t3, t2, t3);

            uint[] r = t2;

			SecP384R1Field.squareN(t3, 120, r);
			SecP384R1Field.multiply(r, t3, r);

			SecP384R1Field.squareN(r, 15, r);
			SecP384R1Field.multiply(r, t4, r);

			SecP384R1Field.squareN(r, 33, r);
			SecP384R1Field.multiply(r, t1, r);

			SecP384R1Field.squareN(r, 64, r);
			SecP384R1Field.multiply(r, x1, r);

			SecP384R1Field.squareN(r, 30, t1);
			SecP384R1Field.square(t1, t2);

			return Nat.eq(12, x1, t2) ? new SecP384R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP384R1FieldElement))
			{
				return false;
			}

			SecP384R1FieldElement o = (SecP384R1FieldElement)other;
			return Nat.eq(12, x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 12);
		}
	}

}