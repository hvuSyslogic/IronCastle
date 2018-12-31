using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	public class SecP192R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP192R1Curve.q;

		protected internal uint[] x;

		public SecP192R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP192R1FieldElement");
			}

			this.x = SecP192R1Field.fromBigInteger(x);
		}

		public SecP192R1FieldElement()
		{
			this.x = Nat192.create();
		}

		public SecP192R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat192.isZero(x);
		}

		public override bool isOne()
		{
			return Nat192.isOne(x);
		}

		public override bool testBitZero()
		{
			return Nat192.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat192.toBigInteger(x);
		}

		public override string getFieldName()
		{
			return "SecP192R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192R1Field.add(x, ((SecP192R1FieldElement)b).x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat192.create();
			SecP192R1Field.addOne(x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192R1Field.subtract(x, ((SecP192R1FieldElement)b).x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192R1Field.multiply(x, ((SecP192R1FieldElement)b).x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat192.create();
			Mod.invert(SecP192R1Field.P, ((SecP192R1FieldElement)b).x, z);
			SecP192R1Field.multiply(z, x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat192.create();
			SecP192R1Field.negate(x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat192.create();
			SecP192R1Field.square(x, z);
			return new SecP192R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP192R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat192.create();
			Mod.invert(SecP192R1Field.P, x, z);
			return new SecP192R1FieldElement(z);
		}

		// D.1.4 91
		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			// Raise this element to the exponent 2^190 - 2^62

			uint[] x1 = this.x;
			if (Nat192.isZero(x1) || Nat192.isOne(x1))
			{
				return this;
			}

			uint[] t1 = Nat192.create();
			uint[] t2 = Nat192.create();

			SecP192R1Field.square(x1, t1);
			SecP192R1Field.multiply(t1, x1, t1);

			SecP192R1Field.squareN(t1, 2, t2);
			SecP192R1Field.multiply(t2, t1, t2);

			SecP192R1Field.squareN(t2, 4, t1);
			SecP192R1Field.multiply(t1, t2, t1);

			SecP192R1Field.squareN(t1, 8, t2);
			SecP192R1Field.multiply(t2, t1, t2);

			SecP192R1Field.squareN(t2, 16, t1);
			SecP192R1Field.multiply(t1, t2, t1);

			SecP192R1Field.squareN(t1, 32, t2);
			SecP192R1Field.multiply(t2, t1, t2);

			SecP192R1Field.squareN(t2, 64, t1);
			SecP192R1Field.multiply(t1, t2, t1);

			SecP192R1Field.squareN(t1, 62, t1);
			SecP192R1Field.square(t1, t2);

			return Nat192.eq(x1, t2) ? new SecP192R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP192R1FieldElement))
			{
				return false;
			}

			SecP192R1FieldElement o = (SecP192R1FieldElement)other;
			return Nat192.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 6);
		}
	}

}