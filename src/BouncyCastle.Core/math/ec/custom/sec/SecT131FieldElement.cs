using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat192 = org.bouncycastle.math.raw.Nat192;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT131FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal long[] x;

		public SecT131FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 131)
			{
				throw new IllegalArgumentException("x value invalid for SecT131FieldElement");
			}

			this.x = SecT131Field.fromBigInteger(x);
		}

		public SecT131FieldElement()
		{
			this.x = Nat192.create64();
		}

		public SecT131FieldElement(long[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat192.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat192.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat192.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT131Field";
		}

		public override int getFieldSize()
		{
			return 131;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			long[] z = Nat192.create64();
			SecT131Field.add(x, ((SecT131FieldElement)b).x, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			long[] z = Nat192.create64();
			SecT131Field.addOne(x, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			long[] z = Nat192.create64();
			SecT131Field.multiply(x, ((SecT131FieldElement)b).x, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x, bx = ((SecT131FieldElement)b).x;
			long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

			long[] tt = Nat.create64(5);
			SecT131Field.multiplyAddToExt(ax, bx, tt);
			SecT131Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat192.create64();
			SecT131Field.reduce(tt, z);
			return new SecT131FieldElement(z);
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
			long[] z = Nat192.create64();
			SecT131Field.square(x, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x;
			long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

			long[] tt = Nat.create64(5);
			SecT131Field.squareAddToExt(ax, tt);
			SecT131Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat192.create64();
			SecT131Field.reduce(tt, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			long[] z = Nat192.create64();
			SecT131Field.squareN(x, pow, z);
			return new SecT131FieldElement(z);
		}

		public override int trace()
		{
			return SecT131Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			long[] z = Nat192.create64();
			SecT131Field.invert(x, z);
			return new SecT131FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			long[] z = Nat192.create64();
			SecT131Field.sqrt(x, z);
			return new SecT131FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.PPB;
		}

		public virtual int getM()
		{
			return 131;
		}

		public virtual int getK1()
		{
			return 2;
		}

		public virtual int getK2()
		{
			return 3;
		}

		public virtual int getK3()
		{
			return 8;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecT131FieldElement))
			{
				return false;
			}

			SecT131FieldElement o = (SecT131FieldElement)other;
			return Nat192.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 131832 ^ Arrays.GetHashCode(x, 0, 3);
		}
	}

}