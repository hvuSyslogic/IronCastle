﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	public class SecP192K1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SecP192K1Curve.q;

		protected internal uint[] x;

		public SecP192K1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SecP192K1FieldElement");
			}

			this.x = SecP192K1Field.fromBigInteger(x);
		}

		public SecP192K1FieldElement()
		{
			this.x = Nat192.create();
		}

		public SecP192K1FieldElement(uint[] x)
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
			return "SecP192K1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192K1Field.add(x, ((SecP192K1FieldElement)b).x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			uint[] z = Nat192.create();
			SecP192K1Field.addOne(x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192K1Field.subtract(x, ((SecP192K1FieldElement)b).x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			uint[] z = Nat192.create();
			SecP192K1Field.multiply(x, ((SecP192K1FieldElement)b).x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			uint[] z = Nat192.create();
			Mod.invert(SecP192K1Field.P, ((SecP192K1FieldElement)b).x, z);
			SecP192K1Field.multiply(z, x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			uint[] z = Nat192.create();
			SecP192K1Field.negate(x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			uint[] z = Nat192.create();
			SecP192K1Field.square(x, z);
			return new SecP192K1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SecP192K1FieldElement(toBigInteger().modInverse(Q));
			uint[] z = Nat192.create();
			Mod.invert(SecP192K1Field.P, x, z);
			return new SecP192K1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Raise this element to the exponent 2^190 - 2^30 - 2^10 - 2^6 - 2^5 - 2^4 - 2^1
			 *
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 * { 159 1s } { 1 0s } { 19 1s } { 1 0s } { 3 1s } { 3 0s} { 3 1s } { 1 0s }
			 *
			 * Therefore we need an addition chain containing 3, 19, 159 (the lengths of the repunits)
			 * We use: 1, 2, [3], 6, 8, 16, [19], 35, 70, 140, [159]
			 */

			uint[] x1 = this.x;
			if (Nat192.isZero(x1) || Nat192.isOne(x1))
			{
				return this;
			}

			uint[] x2 = Nat192.create();
			SecP192K1Field.square(x1, x2);
			SecP192K1Field.multiply(x2, x1, x2);
			uint[] x3 = Nat192.create();
			SecP192K1Field.square(x2, x3);
			SecP192K1Field.multiply(x3, x1, x3);
			uint[] x6 = Nat192.create();
			SecP192K1Field.squareN(x3, 3, x6);
			SecP192K1Field.multiply(x6, x3, x6);
			uint[] x8 = x6;
			SecP192K1Field.squareN(x6, 2, x8);
			SecP192K1Field.multiply(x8, x2, x8);
			uint[] x16 = x2;
			SecP192K1Field.squareN(x8, 8, x16);
			SecP192K1Field.multiply(x16, x8, x16);
			uint[] x19 = x8;
			SecP192K1Field.squareN(x16, 3, x19);
			SecP192K1Field.multiply(x19, x3, x19);
			uint[] x35 = Nat192.create();
			SecP192K1Field.squareN(x19, 16, x35);
			SecP192K1Field.multiply(x35, x16, x35);
			uint[] x70 = x16;
			SecP192K1Field.squareN(x35, 35, x70);
			SecP192K1Field.multiply(x70, x35, x70);
			uint[] x140 = x35;
			SecP192K1Field.squareN(x70, 70, x140);
			SecP192K1Field.multiply(x140, x70, x140);
			uint[] x159 = x70;
			SecP192K1Field.squareN(x140, 19, x159);
			SecP192K1Field.multiply(x159, x19, x159);

			uint[] t1 = x159;
			SecP192K1Field.squareN(t1, 20, t1);
			SecP192K1Field.multiply(t1, x19, t1);
			SecP192K1Field.squareN(t1, 4, t1);
			SecP192K1Field.multiply(t1, x3, t1);
			SecP192K1Field.squareN(t1, 6, t1);
			SecP192K1Field.multiply(t1, x3, t1);
			SecP192K1Field.square(t1, t1);

			uint[] t2 = x3;
			SecP192K1Field.square(t1, t2);

			return Nat192.eq(x1, t2) ? new SecP192K1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecP192K1FieldElement))
			{
				return false;
			}

			SecP192K1FieldElement o = (SecP192K1FieldElement)other;
			return Nat192.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 6);
		}
	}

}