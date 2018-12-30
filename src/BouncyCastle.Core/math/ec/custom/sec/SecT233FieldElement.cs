using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT233FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal long[] x;

		public SecT233FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 233)
			{
				throw new IllegalArgumentException("x value invalid for SecT233FieldElement");
			}

			this.x = SecT233Field.fromBigInteger(x);
		}

		public SecT233FieldElement()
		{
			this.x = Nat256.create64();
		}

		public SecT233FieldElement(long[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat256.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat256.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat256.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT233Field";
		}

		public override int getFieldSize()
		{
			return 233;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			long[] z = Nat256.create64();
			SecT233Field.add(x, ((SecT233FieldElement)b).x, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			long[] z = Nat256.create64();
			SecT233Field.addOne(x, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			long[] z = Nat256.create64();
			SecT233Field.multiply(x, ((SecT233FieldElement)b).x, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x, bx = ((SecT233FieldElement)b).x;
			long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

			long[] tt = Nat256.createExt64();
			SecT233Field.multiplyAddToExt(ax, bx, tt);
			SecT233Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat256.create64();
			SecT233Field.reduce(tt, z);
			return new SecT233FieldElement(z);
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
			long[] z = Nat256.create64();
			SecT233Field.square(x, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			long[] ax = this.x;
			long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

			long[] tt = Nat256.createExt64();
			SecT233Field.squareAddToExt(ax, tt);
			SecT233Field.multiplyAddToExt(xx, yx, tt);

			long[] z = Nat256.create64();
			SecT233Field.reduce(tt, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			long[] z = Nat256.create64();
			SecT233Field.squareN(x, pow, z);
			return new SecT233FieldElement(z);
		}

		public override int trace()
		{
			return SecT233Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			long[] z = Nat256.create64();
			SecT233Field.invert(x, z);
			return new SecT233FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			long[] z = Nat256.create64();
			SecT233Field.sqrt(x, z);
			return new SecT233FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.TPB;
		}

		public virtual int getM()
		{
			return 233;
		}

		public virtual int getK1()
		{
			return 74;
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

			if (!(other is SecT233FieldElement))
			{
				return false;
			}

			SecT233FieldElement o = (SecT233FieldElement)other;
			return Nat256.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 2330074 ^ Arrays.GetHashCode(x, 0, 4);
		}
	}

}