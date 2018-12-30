using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecP256R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP256R1Curve.q;

		protected internal uint[] x;

		public SecP256R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP256R1FieldElement");
			}

			this.x = SecP256R1Field.fromBigInteger(x);
		}

		public SecP256R1FieldElement()
		{
			this.x = Nat256.create();
		}

		public SecP256R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat256.isZero(x);
		}

		public override bool isOne()
		{
			return Nat256.isOne(x);
		}

		public override bool testBitZero()
		{
			return Nat256.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat256.toBigInteger(x);
		}

		public override string getFieldName()
		{
			return "SecP256R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256R1Field.add(x, ((SecP256R1FieldElement)b).x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat256.create();
			SecP256R1Field.addOne(x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256R1Field.subtract(x, ((SecP256R1FieldElement)b).x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256R1Field.multiply(x, ((SecP256R1FieldElement)b).x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat256.create();
			Mod.invert(SecP256R1Field.P, ((SecP256R1FieldElement)b).x, z);
			SecP256R1Field.multiply(z, x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat256.create();
			SecP256R1Field.negate(x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat256.create();
			SecP256R1Field.square(x, z);
			return new SecP256R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP256R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat256.create();
			Mod.invert(SecP256R1Field.P, x, z);
			return new SecP256R1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			// Raise this element to the exponent 2^254 - 2^222 + 2^190 + 2^94

			uint[] x1 = this.x;
			if (Nat256.isZero(x1) || Nat256.isOne(x1))
			{
				return this;
			}

			uint[] t1 = Nat256.create();
			uint[] t2 = Nat256.create();

			SecP256R1Field.square(x1, t1);
			SecP256R1Field.multiply(t1, x1, t1);

			SecP256R1Field.squareN(t1, 2, t2);
			SecP256R1Field.multiply(t2, t1, t2);

			SecP256R1Field.squareN(t2, 4, t1);
			SecP256R1Field.multiply(t1, t2, t1);

			SecP256R1Field.squareN(t1, 8, t2);
			SecP256R1Field.multiply(t2, t1, t2);

			SecP256R1Field.squareN(t2, 16, t1);
			SecP256R1Field.multiply(t1, t2, t1);

			SecP256R1Field.squareN(t1, 32, t1);
			SecP256R1Field.multiply(t1, x1, t1);

			SecP256R1Field.squareN(t1, 96, t1);
			SecP256R1Field.multiply(t1, x1, t1);

			SecP256R1Field.squareN(t1, 94, t1);
			SecP256R1Field.square(t1, t2);

			return Nat256.eq(x1, t2) ? new SecP256R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP256R1FieldElement))
			{
				return false;
			}

			SecP256R1FieldElement o = (SecP256R1FieldElement)other;
			return Nat256.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 8);
		}
	}

}