using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	
	public class SecP521R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP521R1Curve.q;

		protected internal uint[] x;

		public SecP521R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP521R1FieldElement");
			}

			this.x = SecP521R1Field.fromBigInteger(x);
		}

		public SecP521R1FieldElement()
		{
			this.x = Nat.create(17);
		}

		public SecP521R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat.isZero(17, x);
		}

		public override bool isOne()
		{
			return Nat.isOne(17, x);
		}

		public override bool testBitZero()
		{
			return Nat.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat.toBigInteger(17, x);
		}

		public override string getFieldName()
		{
			return "SecP521R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.add(x, ((SecP521R1FieldElement)b).x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.addOne(x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.subtract(x, ((SecP521R1FieldElement)b).x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.multiply(x, ((SecP521R1FieldElement)b).x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat.create(17);
			Mod.invert(SecP521R1Field.P, ((SecP521R1FieldElement)b).x, z);
			SecP521R1Field.multiply(z, x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.negate(x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat.create(17);
			SecP521R1Field.square(x, z);
			return new SecP521R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP521R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat.create(17);
			Mod.invert(SecP521R1Field.P, x, z);
			return new SecP521R1FieldElement(z);
		}

		// D.1.4 91
		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			// Raise this element to the exponent 2^519

			uint[] x1 = this.x;
			if (Nat.isZero(17, x1) || Nat.isOne(17, x1))
			{
				return this;
			}

			uint[] t1 = Nat.create(17);
			uint[] t2 = Nat.create(17);

			SecP521R1Field.squareN(x1, 519, t1);
			SecP521R1Field.square(t1, t2);

			return Nat.eq(17, x1, t2) ? new SecP521R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP521R1FieldElement))
			{
				return false;
			}

			SecP521R1FieldElement o = (SecP521R1FieldElement)other;
			return Nat.eq(17, x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 17);
		}
	}

}