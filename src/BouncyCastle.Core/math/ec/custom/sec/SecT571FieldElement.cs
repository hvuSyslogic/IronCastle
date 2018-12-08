using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat576 = org.bouncycastle.math.raw.Nat576;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT571FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal long[] x;

		public SecT571FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 571)
			{
				throw new IllegalArgumentException("x value invalid for SecT571FieldElement");
			}

			this.x = SecT571Field.fromBigInteger(x);
		}

		public SecT571FieldElement()
		{
			this.x = Nat576.create64();
		}

		public SecT571FieldElement(long[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat576.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat576.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat576.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT571Field";
		}

		public override int getFieldSize()
		{
			return 571;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			long[] z = Nat576.create64();
			SecT571Field.add(x, ((SecT571FieldElement)b).x, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			long[] z = Nat576.create64();
			SecT571Field.addOne(x, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			long[] z = Nat576.create64();
			SecT571Field.multiply(x, ((SecT571FieldElement)b).x, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x, bx = ((SecT571FieldElement)b).x;
			long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

			long[] tt = Nat576.createExt64();
			SecT571Field.multiplyAddToExt(ax, bx, tt);
			SecT571Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat576.create64();
			SecT571Field.reduce(tt, z);
			return new SecT571FieldElement(z);
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
			long[] z = Nat576.create64();
			SecT571Field.square(x, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x;
			long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

			long[] tt = Nat576.createExt64();
			SecT571Field.squareAddToExt(ax, tt);
			SecT571Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat576.create64();
			SecT571Field.reduce(tt, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			long[] z = Nat576.create64();
			SecT571Field.squareN(x, pow, z);
			return new SecT571FieldElement(z);
		}

		public override int trace()
		{
			return SecT571Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			long[] z = Nat576.create64();
			SecT571Field.invert(x, z);
			return new SecT571FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			long[] z = Nat576.create64();
			SecT571Field.sqrt(x, z);
			return new SecT571FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.PPB;
		}

		public virtual int getM()
		{
			return 571;
		}

		public virtual int getK1()
		{
			return 2;
		}

		public virtual int getK2()
		{
			return 5;
		}

		public virtual int getK3()
		{
			return 10;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecT571FieldElement))
			{
				return false;
			}

			SecT571FieldElement o = (SecT571FieldElement)other;
			return Nat576.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 5711052 ^ Arrays.GetHashCode(x, 0, 9);
		}
	}

}