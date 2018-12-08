using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.gm
{

	using Mod = org.bouncycastle.math.raw.Mod;
	using Nat256 = org.bouncycastle.math.raw.Nat256;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SM2P256V1FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = SM2P256V1Curve.q;

		protected internal int[] x;

		public SM2P256V1FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for SM2P256V1FieldElement");
			}

			this.x = SM2P256V1Field.fromBigInteger(x);
		}

		public SM2P256V1FieldElement()
		{
			this.x = Nat256.create();
		}

		public SM2P256V1FieldElement(int[] x)
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
			return "SM2P256V1Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			int[] z = Nat256.create();
			SM2P256V1Field.add(x, ((SM2P256V1FieldElement)b).x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			int[] z = Nat256.create();
			SM2P256V1Field.addOne(x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			int[] z = Nat256.create();
			SM2P256V1Field.subtract(x, ((SM2P256V1FieldElement)b).x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			int[] z = Nat256.create();
			SM2P256V1Field.multiply(x, ((SM2P256V1FieldElement)b).x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			int[] z = Nat256.create();
			Mod.invert(SM2P256V1Field.P, ((SM2P256V1FieldElement)b).x, z);
			SM2P256V1Field.multiply(z, x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			int[] z = Nat256.create();
			SM2P256V1Field.negate(x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement square()
		{
			int[] z = Nat256.create();
			SM2P256V1Field.square(x, z);
			return new SM2P256V1FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new SM2P256V1FieldElement(toBigInteger().modInverse(Q));
			int[] z = Nat256.create();
			Mod.invert(SM2P256V1Field.P, x, z);
			return new SM2P256V1FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Raise this element to the exponent 2^254 - 2^222 - 2^94 + 2^62
			 *
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 * { 31 1s } { 1 0s } { 128 1s } { 31 0s } { 1 1s } { 62 0s}
			 *
			 * We use an addition chain for the beginning: [1], 2, 3, 6, 12, [24], 30, [31] 
			 */

			int[] x1 = this.x;
			if (Nat256.isZero(x1) || Nat256.isOne(x1))
			{
				return this;
			}

			int[] x2 = Nat256.create();
			SM2P256V1Field.square(x1, x2);
			SM2P256V1Field.multiply(x2, x1, x2);
			int[] x4 = Nat256.create();
			SM2P256V1Field.squareN(x2, 2, x4);
			SM2P256V1Field.multiply(x4, x2, x4);
			int[] x6 = Nat256.create();
			SM2P256V1Field.squareN(x4, 2, x6);
			SM2P256V1Field.multiply(x6, x2, x6);
			int[] x12 = x2;
			SM2P256V1Field.squareN(x6, 6, x12);
			SM2P256V1Field.multiply(x12, x6, x12);
			int[] x24 = Nat256.create();
			SM2P256V1Field.squareN(x12, 12, x24);
			SM2P256V1Field.multiply(x24, x12, x24);
			int[] x30 = x12;
			SM2P256V1Field.squareN(x24, 6, x30);
			SM2P256V1Field.multiply(x30, x6, x30);
			int[] x31 = x6;
			SM2P256V1Field.square(x30, x31);
			SM2P256V1Field.multiply(x31, x1, x31);

			int[] t1 = x24;
			SM2P256V1Field.squareN(x31, 31, t1);

			int[] x62 = x30;
			SM2P256V1Field.multiply(t1, x31, x62);

			SM2P256V1Field.squareN(t1, 32, t1);
			SM2P256V1Field.multiply(t1, x62, t1);
			SM2P256V1Field.squareN(t1, 62, t1);
			SM2P256V1Field.multiply(t1, x62, t1);
			SM2P256V1Field.squareN(t1, 4, t1);
			SM2P256V1Field.multiply(t1, x4, t1);
			SM2P256V1Field.squareN(t1, 32, t1);
			SM2P256V1Field.multiply(t1, x1, t1);
			SM2P256V1Field.squareN(t1, 62, t1);

			int[] t2 = x4;
			SM2P256V1Field.square(t1, t2);

			return Nat256.eq(x1, t2) ? new SM2P256V1FieldElement(t1) : null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SM2P256V1FieldElement))
			{
				return false;
			}

			SM2P256V1FieldElement o = (SM2P256V1FieldElement)other;
			return Nat256.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 8);
		}
	}

}