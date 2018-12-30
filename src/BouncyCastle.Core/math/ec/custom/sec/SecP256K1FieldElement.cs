using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecP256K1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP256K1Curve.q;

		protected internal uint[] x;

		public SecP256K1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP256K1FieldElement");
			}

			this.x = SecP256K1Field.fromBigInteger(x);
		}

		public SecP256K1FieldElement()
		{
			this.x = Nat256.create();
		}

		public SecP256K1FieldElement(uint[] x)
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
			return "SecP256K1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256K1Field.add(x, ((SecP256K1FieldElement)b).x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat256.create();
			SecP256K1Field.addOne(x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256K1Field.subtract(x, ((SecP256K1FieldElement)b).x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat256.create();
			SecP256K1Field.multiply(x, ((SecP256K1FieldElement)b).x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat256.create();
			Mod.invert(SecP256K1Field.P, ((SecP256K1FieldElement)b).x, z);
			SecP256K1Field.multiply(z, x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat256.create();
			SecP256K1Field.negate(x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat256.create();
			SecP256K1Field.square(x, z);
			return new SecP256K1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP256K1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat256.create();
			Mod.invert(SecP256K1Field.P, x, z);
			return new SecP256K1FieldElement(z);
		}

		// D.1.4 91
		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Raise this element to the exponent 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2
			 *
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 * { 223 1s } { 1 0s } { 22 1s } { 4 0s } { 2 1s } { 2 0s}
			 *
			 * Therefore we need an addition chain containing 2, 22, 223 (the lengths of the repunits)
			 * We use: 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
			 */

			uint[] x1 = this.x;
			if (Nat256.isZero(x1) || Nat256.isOne(x1))
			{
				return this;
			}

			uint[] x2 = Nat256.create();
			SecP256K1Field.square(x1, x2);
			SecP256K1Field.multiply(x2, x1, x2);
			uint[] x3 = Nat256.create();
			SecP256K1Field.square(x2, x3);
			SecP256K1Field.multiply(x3, x1, x3);
			uint[] x6 = Nat256.create();
			SecP256K1Field.squareN(x3, 3, x6);
			SecP256K1Field.multiply(x6, x3, x6);
			uint[] x9 = x6;
			SecP256K1Field.squareN(x6, 3, x9);
			SecP256K1Field.multiply(x9, x3, x9);
			uint[] x11 = x9;
			SecP256K1Field.squareN(x9, 2, x11);
			SecP256K1Field.multiply(x11, x2, x11);
			uint[] x22 = Nat256.create();
			SecP256K1Field.squareN(x11, 11, x22);
			SecP256K1Field.multiply(x22, x11, x22);
			uint[] x44 = x11;
			SecP256K1Field.squareN(x22, 22, x44);
			SecP256K1Field.multiply(x44, x22, x44);
			uint[] x88 = Nat256.create();
			SecP256K1Field.squareN(x44, 44, x88);
			SecP256K1Field.multiply(x88, x44, x88);
			uint[] x176 = Nat256.create();
			SecP256K1Field.squareN(x88, 88, x176);
			SecP256K1Field.multiply(x176, x88, x176);
			uint[] x220 = x88;
			SecP256K1Field.squareN(x176, 44, x220);
			SecP256K1Field.multiply(x220, x44, x220);
			uint[] x223 = x44;
			SecP256K1Field.squareN(x220, 3, x223);
			SecP256K1Field.multiply(x223, x3, x223);

			uint[] t1 = x223;
			SecP256K1Field.squareN(t1, 23, t1);
			SecP256K1Field.multiply(t1, x22, t1);
			SecP256K1Field.squareN(t1, 6, t1);
			SecP256K1Field.multiply(t1, x2, t1);
			SecP256K1Field.squareN(t1, 2, t1);

			uint[] t2 = x2;
			SecP256K1Field.square(t1, t2);

			return Nat256.eq(x1, t2) ? new SecP256K1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP256K1FieldElement))
			{
				return false;
			}

			SecP256K1FieldElement o = (SecP256K1FieldElement)other;
			return Nat256.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 8);
		}
	}

}