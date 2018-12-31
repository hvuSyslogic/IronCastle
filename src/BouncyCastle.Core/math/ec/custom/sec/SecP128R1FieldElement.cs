using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	public class SecP128R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP128R1Curve.q;

		protected internal uint[] x;

		public SecP128R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP128R1FieldElement");
			}

			this.x = SecP128R1Field.fromBigInteger(x);
		}

		public SecP128R1FieldElement()
		{
			this.x = Nat128.create();
		}

		public SecP128R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat128.isZero(x);
		}

		public override bool isOne()
		{
			return Nat128.isOne(x);
		}

		public override bool testBitZero()
		{
			return Nat128.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat128.toBigInteger(x);
		}

		public override string getFieldName()
		{
			return "SecP128R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat128.create();
			SecP128R1Field.add(x, ((SecP128R1FieldElement)b).x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat128.create();
			SecP128R1Field.addOne(x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat128.create();
			SecP128R1Field.subtract(x, ((SecP128R1FieldElement)b).x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat128.create();
			SecP128R1Field.multiply(x, ((SecP128R1FieldElement)b).x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat128.create();
			Mod.invert(SecP128R1Field.P, ((SecP128R1FieldElement)b).x, z);
			SecP128R1Field.multiply(z, x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat128.create();
			SecP128R1Field.negate(x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat128.create();
			SecP128R1Field.square(x, z);
			return new SecP128R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP128R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat128.create();
			Mod.invert(SecP128R1Field.P, x, z);
			return new SecP128R1FieldElement(z);
		}

		// D.1.4 91
		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Raise this element to the exponent 2^126 - 2^95
			 *
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 *     { 31 1s } { 95 0s }
			 *
			 * Therefore we need an addition chain containing 31 (the length of the repunit) We use:
			 *     1, 2, 4, 8, 10, 20, 30, [31]
			 */

			uint[] x1 = this.x;
			if (Nat128.isZero(x1) || Nat128.isOne(x1))
			{
				return this;
			}

			uint[] x2 = Nat128.create();
			SecP128R1Field.square(x1, x2);
			SecP128R1Field.multiply(x2, x1, x2);
			uint[] x4 = Nat128.create();
			SecP128R1Field.squareN(x2, 2, x4);
			SecP128R1Field.multiply(x4, x2, x4);
			uint[] x8 = Nat128.create();
			SecP128R1Field.squareN(x4, 4, x8);
			SecP128R1Field.multiply(x8, x4, x8);
			uint[] x10 = x4;
			SecP128R1Field.squareN(x8, 2, x10);
			SecP128R1Field.multiply(x10, x2, x10);
			uint[] x20 = x2;
			SecP128R1Field.squareN(x10, 10, x20);
			SecP128R1Field.multiply(x20, x10, x20);
			uint[] x30 = x8;
			SecP128R1Field.squareN(x20, 10, x30);
			SecP128R1Field.multiply(x30, x10, x30);
			uint[] x31 = x10;
			SecP128R1Field.square(x30, x31);
			SecP128R1Field.multiply(x31, x1, x31);

			uint[] t1 = x31;
			SecP128R1Field.squareN(t1, 95, t1);

			uint[] t2 = x30;
			SecP128R1Field.square(t1, t2);

			return Nat128.eq(x1, t2) ? new SecP128R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP128R1FieldElement))
			{
				return false;
			}

			SecP128R1FieldElement o = (SecP128R1FieldElement)other;
			return Nat128.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 4);
		}
	}

}