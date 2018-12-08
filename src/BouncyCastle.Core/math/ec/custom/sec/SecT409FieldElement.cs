using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat448 = org.bouncycastle.math.raw.Nat448;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT409FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal long[] x;

		public SecT409FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 409)
			{
				throw new IllegalArgumentException("x value invalid for SecT409FieldElement");
			}

			this.x = SecT409Field.fromBigInteger(x);
		}

		public SecT409FieldElement()
		{
			this.x = Nat448.create64();
		}

		public SecT409FieldElement(long[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat448.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat448.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat448.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT409Field";
		}

		public override int getFieldSize()
		{
			return 409;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			long[] z = Nat448.create64();
			SecT409Field.add(x, ((SecT409FieldElement)b).x, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			long[] z = Nat448.create64();
			SecT409Field.addOne(x, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			long[] z = Nat448.create64();
			SecT409Field.multiply(x, ((SecT409FieldElement)b).x, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x, bx = ((SecT409FieldElement)b).x;
			long[] xx = ((SecT409FieldElement)x).x, yx = ((SecT409FieldElement)y).x;

			long[] tt = Nat.create64(13);
			SecT409Field.multiplyAddToExt(ax, bx, tt);
			SecT409Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat448.create64();
			SecT409Field.reduce(tt, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement divide(ECFieldElement b)
		{
			return multiply(b.invert());
		}

		public override ECFieldElement negate()
		{
			return this;
		}

		public override ECFieldElement square()
		{
			long[] z = Nat448.create64();
			SecT409Field.square(x, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x;
			long[] xx = ((SecT409FieldElement)x).x, yx = ((SecT409FieldElement)y).x;

			long[] tt = Nat.create64(13);
			SecT409Field.squareAddToExt(ax, tt);
			SecT409Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat448.create64();
			SecT409Field.reduce(tt, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			long[] z = Nat448.create64();
			SecT409Field.squareN(x, pow, z);
			return new SecT409FieldElement(z);
		}

		public override int trace()
		{
			return SecT409Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			long[] z = Nat448.create64();
			SecT409Field.invert(x, z);
			return new SecT409FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			long[] z = Nat448.create64();
			SecT409Field.sqrt(x, z);
			return new SecT409FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.TPB;
		}

		public virtual int getM()
		{
			return 409;
		}

		public virtual int getK1()
		{
			return 87;
		}

		public virtual int getK2()
		{
			return 0;
		}

		public virtual int getK3()
		{
			return 0;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecT409FieldElement))
			{
				return false;
			}

			SecT409FieldElement o = (SecT409FieldElement)other;
			return Nat448.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 4090087 ^ Arrays.GetHashCode(x, 0, 7);
		}
	}

}