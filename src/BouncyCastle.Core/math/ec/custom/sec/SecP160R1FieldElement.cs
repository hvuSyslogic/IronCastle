using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecP160R1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP160R1Curve.q;

		protected internal uint[] x;

		public SecP160R1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP160R1FieldElement");
			}

			this.x = SecP160R1Field.fromBigInteger(x);
		}

		public SecP160R1FieldElement()
		{
			this.x = Nat160.create();
		}

		public SecP160R1FieldElement(uint[] x)
		{
			this.x = x;
		}

		public override bool isZero()
		{
			return Nat160.isZero(x);
		}

		public override bool isOne()
		{
			return Nat160.isOne(x);
		}

		public override bool testBitZero()
		{
			return Nat160.getBit(x, 0) == 1;
		}

		public override BigInteger toBigInteger()
		{
			return Nat160.toBigInteger(x);
		}

		public override string getFieldName()
		{
			return "SecP160R1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat160.create();
			SecP160R1Field.add(x, ((SecP160R1FieldElement)b).x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat160.create();
			SecP160R1Field.addOne(x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat160.create();
			SecP160R1Field.subtract(x, ((SecP160R1FieldElement)b).x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat160.create();
			SecP160R1Field.multiply(x, ((SecP160R1FieldElement)b).x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat160.create();
			Mod.invert(SecP160R1Field.P, ((SecP160R1FieldElement)b).x, z);
			SecP160R1Field.multiply(z, x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat160.create();
			SecP160R1Field.negate(x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat160.create();
			SecP160R1Field.square(x, z);
			return new SecP160R1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP160R1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat160.create();
			Mod.invert(SecP160R1Field.P, x, z);
			return new SecP160R1FieldElement(z);
		}

		// D.1.4 91
		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Raise this element to the exponent 2^158 - 2^29
			 *
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 *     { 129 1s } { 29 0s }
			 *
			 * Therefore we need an addition chain containing 129 (the length of the repunit) We use:
			 *     1, 2, 4, 8, 16, 32, 64, 128, [129]
			 */

			uint[] x1 = this.x;
			if (Nat160.isZero(x1) || Nat160.isOne(x1))
			{
				return this;
			}

			uint[] x2 = Nat160.create();
			SecP160R1Field.square(x1, x2);
			SecP160R1Field.multiply(x2, x1, x2);
			uint[] x4 = Nat160.create();
			SecP160R1Field.squareN(x2, 2, x4);
			SecP160R1Field.multiply(x4, x2, x4);
			var x8 = x2;
			SecP160R1Field.squareN(x4, 4, x8);
			SecP160R1Field.multiply(x8, x4, x8);
			var x16 = x4;
			SecP160R1Field.squareN(x8, 8, x16);
			SecP160R1Field.multiply(x16, x8, x16);
			var x32 = x8;
			SecP160R1Field.squareN(x16, 16, x32);
			SecP160R1Field.multiply(x32, x16, x32);
			var x64 = x16;
			SecP160R1Field.squareN(x32, 32, x64);
			SecP160R1Field.multiply(x64, x32, x64);
			var x128 = x32;
			SecP160R1Field.squareN(x64, 64, x128);
			SecP160R1Field.multiply(x128, x64, x128);
            var x129 = x64;
			SecP160R1Field.square(x128, x129);
			SecP160R1Field.multiply(x129, x1, x129);

            var t1 = x129;
			SecP160R1Field.squareN(t1, 29, t1);

            var t2 = x128;
			SecP160R1Field.square(t1, t2);

			return Nat160.eq(x1, t2) ? new SecP160R1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP160R1FieldElement))
			{
				return false;
			}

			SecP160R1FieldElement o = (SecP160R1FieldElement)other;
			return Nat160.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 5);
		}
	}

}