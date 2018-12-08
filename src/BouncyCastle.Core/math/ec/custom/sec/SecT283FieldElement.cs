using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat = org.bouncycastle.math.raw.Nat;
	using Nat320 = org.bouncycastle.math.raw.Nat320;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT283FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal long[] x;

		public SecT283FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 283)
			{
				throw new IllegalArgumentException("x value invalid for SecT283FieldElement");
			}

			this.x = SecT283Field.fromBigInteger(x);
		}

		public SecT283FieldElement()
		{
			this.x = Nat320.create64();
		}

		public SecT283FieldElement(long[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat320.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat320.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat320.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT283Field";
		}

		public override int getFieldSize()
		{
			return 283;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			long[] z = Nat320.create64();
			SecT283Field.add(x, ((SecT283FieldElement)b).x, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			long[] z = Nat320.create64();
			SecT283Field.addOne(x, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			long[] z = Nat320.create64();
			SecT283Field.multiply(x, ((SecT283FieldElement)b).x, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x, bx = ((SecT283FieldElement)b).x;
			long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

			long[] tt = Nat.create64(9);
			SecT283Field.multiplyAddToExt(ax, bx, tt);
			SecT283Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat320.create64();
			SecT283Field.reduce(tt, z);
			return new SecT283FieldElement(z);
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
			long[] z = Nat320.create64();
			SecT283Field.square(x, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x;
			long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

			long[] tt = Nat.create64(9);
			SecT283Field.squareAddToExt(ax, tt);
			SecT283Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat320.create64();
			SecT283Field.reduce(tt, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			long[] z = Nat320.create64();
			SecT283Field.squareN(x, pow, z);
			return new SecT283FieldElement(z);
		}

		public override int trace()
		{
			return SecT283Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			long[] z = Nat320.create64();
			SecT283Field.invert(x, z);
			return new SecT283FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			long[] z = Nat320.create64();
			SecT283Field.sqrt(x, z);
			return new SecT283FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.PPB;
		}

		public virtual int getM()
		{
			return 283;
		}

		public virtual int getK1()
		{
			return 5;
		}

		public virtual int getK2()
		{
			return 7;
		}

		public virtual int getK3()
		{
			return 12;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecT283FieldElement))
			{
				return false;
			}

			SecT283FieldElement o = (SecT283FieldElement)other;
			return Nat320.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 2831275 ^ Arrays.GetHashCode(x, 0, 5);
		}
	}

}