using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.djb
{

	using Mod = org.bouncycastle.math.raw.Mod;
	using Nat256 = org.bouncycastle.math.raw.Nat256;
	using Arrays = org.bouncycastle.util.Arrays;

	public class Curve25519FieldElement : ECFieldElement.AbstractFp
	{
		public static readonly BigInteger Q = Curve25519.q;

		// Calculated as ECConstants.TWO.modPow(Q.shiftRight(2), Q)
		private static readonly int[] PRECOMP_POW2 = new int[]{0x4a0ea0b0, unchecked((int)0xc4ee1b27), unchecked((int)0xad2fe478), 0x2f431806, 0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480};

		protected internal int[] x;

		public Curve25519FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
			{
				throw new IllegalArgumentException("x value invalid for Curve25519FieldElement");
			}

			this.x = Curve25519Field.fromBigInteger(x);
		}

		public Curve25519FieldElement()
		{
			this.x = Nat256.create();
		}

		public Curve25519FieldElement(int[] x)
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
			return "Curve25519Field";
		}

		public override int getFieldSize()
		{
			return Q.bitLength();
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			int[] z = Nat256.create();
			Curve25519Field.add(x, ((Curve25519FieldElement)b).x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			int[] z = Nat256.create();
			Curve25519Field.addOne(x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			int[] z = Nat256.create();
			Curve25519Field.subtract(x, ((Curve25519FieldElement)b).x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			int[] z = Nat256.create();
			Curve25519Field.multiply(x, ((Curve25519FieldElement)b).x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
	//        return multiply(b.invert());
			int[] z = Nat256.create();
			Mod.invert(Curve25519Field.P, ((Curve25519FieldElement)b).x, z);
			Curve25519Field.multiply(z, x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement negate()
		{
			int[] z = Nat256.create();
			Curve25519Field.negate(x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement square()
		{
			int[] z = Nat256.create();
			Curve25519Field.square(x, z);
			return new Curve25519FieldElement(z);
		}

		public override ECFieldElement invert()
		{
	//        return new Curve25519FieldElement(toBigInteger().modInverse(Q));
			int[] z = Nat256.create();
			Mod.invert(Curve25519Field.P, x, z);
			return new Curve25519FieldElement(z);
		}

		/// <summary>
		/// return a sqrt root - the routine verifies that the calculation returns the right value - if
		/// none exists it returns null.
		/// </summary>
		public override ECFieldElement sqrt()
		{
			/*
			 * Q == 8m + 5, so we use Pocklington's method for this case.
			 *
			 * First, raise this element to the exponent 2^252 - 2^1 (i.e. m + 1)
			 * 
			 * Breaking up the exponent's binary representation into "repunits", we get:
			 * { 251 1s } { 1 0s }
			 * 
			 * Therefore we need an addition chain containing 251 (the lengths of the repunits)
			 * We use: 1, 2, 3, 4, 7, 11, 15, 30, 60, 120, 131, [251]
			 */

			int[] x1 = this.x;
			if (Nat256.isZero(x1) || Nat256.isOne(x1))
			{
				return this;
			}

			int[] x2 = Nat256.create();
			Curve25519Field.square(x1, x2);
			Curve25519Field.multiply(x2, x1, x2);
			int[] x3 = x2;
			Curve25519Field.square(x2, x3);
			Curve25519Field.multiply(x3, x1, x3);
			int[] x4 = Nat256.create();
			Curve25519Field.square(x3, x4);
			Curve25519Field.multiply(x4, x1, x4);
			int[] x7 = Nat256.create();
			Curve25519Field.squareN(x4, 3, x7);
			Curve25519Field.multiply(x7, x3, x7);
			int[] x11 = x3;
			Curve25519Field.squareN(x7, 4, x11);
			Curve25519Field.multiply(x11, x4, x11);
			int[] x15 = x7;
			Curve25519Field.squareN(x11, 4, x15);
			Curve25519Field.multiply(x15, x4, x15);
			int[] x30 = x4;
			Curve25519Field.squareN(x15, 15, x30);
			Curve25519Field.multiply(x30, x15, x30);
			int[] x60 = x15;
			Curve25519Field.squareN(x30, 30, x60);
			Curve25519Field.multiply(x60, x30, x60);
			int[] x120 = x30;
			Curve25519Field.squareN(x60, 60, x120);
			Curve25519Field.multiply(x120, x60, x120);
			int[] x131 = x60;
			Curve25519Field.squareN(x120, 11, x131);
			Curve25519Field.multiply(x131, x11, x131);
			int[] x251 = x11;
			Curve25519Field.squareN(x131, 120, x251);
			Curve25519Field.multiply(x251, x120, x251);

			int[] t1 = x251;
			Curve25519Field.square(t1, t1);

			int[] t2 = x120;
			Curve25519Field.square(t1, t2);

			if (Nat256.eq(x1, t2))
			{
				return new Curve25519FieldElement(t1);
			}

			/*
			 * If the first guess is incorrect, we multiply by a precomputed power of 2 to get the second guess,
			 * which is ((4x)^(m + 1))/2 mod Q
			 */
			Curve25519Field.multiply(t1, PRECOMP_POW2, t1);

			Curve25519Field.square(t1, t2);

			if (Nat256.eq(x1, t2))
			{
				return new Curve25519FieldElement(t1);
			}

			return null;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is Curve25519FieldElement))
			{
				return false;
			}

			Curve25519FieldElement o = (Curve25519FieldElement)other;
			return Nat256.eq(x, o.x);
		}

		public override int GetHashCode()
		{
			return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 8);
		}
	}

}