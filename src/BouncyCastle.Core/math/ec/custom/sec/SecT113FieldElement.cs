using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	public class SecT113FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal ulong[] x;

		public SecT113FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 113)
			{
				throw new IllegalArgumentException("x value invalid for SecT113FieldElement");
			}

			this.x = SecT113Field.fromBigInteger(x);
		}

		public SecT113FieldElement()
		{
			this.x = Nat128.create64();
		}

		public SecT113FieldElement(ulong[] x)
		{
			this.x = x;
		}

	//    public int bitLength()
	//    {
	//        return x.degree();
	//    }

		public override bool isOne()
		{
			return Nat128.isOne64(x);
		}

		public override bool isZero()
		{
			return Nat128.isZero64(x);
		}

		public override bool testBitZero()
		{
			return (x[0] & 1L) != 0L;
		}

		public override BigInteger toBigInteger()
		{
			return Nat128.toBigInteger64(x);
		}

		public override string getFieldName()
		{
			return "SecT113Field";
		}

		public override int getFieldSize()
		{
			return 113;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			ulong[] z = Nat128.create64();
			SecT113Field.add(x, ((SecT113FieldElement)b).x, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			ulong[] z = Nat128.create64();
			SecT113Field.addOne(x, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			ulong[] z = Nat128.create64();
			SecT113Field.multiply(x, ((SecT113FieldElement)b).x, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x, bx = ((SecT113FieldElement)b).x;
			ulong[] xx = ((SecT113FieldElement)x).x, yx = ((SecT113FieldElement)y).x;

			ulong[] tt = Nat128.createExt64();
			SecT113Field.multiplyAddToExt(ax, bx, tt);
			SecT113Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat128.create64();
			SecT113Field.reduce(tt, z);
			return new SecT113FieldElement(z);
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
			ulong[] z = Nat128.create64();
			SecT113Field.square(x, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
            ulong[] ax = this.x;
            ulong[] xx = ((SecT113FieldElement)x).x, yx = ((SecT113FieldElement)y).x;

			ulong[] tt = Nat128.createExt64();
			SecT113Field.squareAddToExt(ax, tt);
			SecT113Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat128.create64();
			SecT113Field.reduce(tt, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			ulong[] z = Nat128.create64();
			SecT113Field.squareN(x, pow, z);
			return new SecT113FieldElement(z);
		}

		public override uint trace()
		{
			return SecT113Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			ulong[] z = Nat128.create64();
			SecT113Field.invert(x, z);
			return new SecT113FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			ulong[] z = Nat128.create64();
			SecT113Field.sqrt(x, z);
			return new SecT113FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.TPB;
		}

		public virtual int getM()
		{
			return 113;
		}

		public virtual int getK1()
		{
			return 9;
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

			if (!(other is SecT113FieldElement))
			{
				return false;
			}

			SecT113FieldElement o = (SecT113FieldElement)other;
			return Nat128.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 113009 ^ Arrays.GetHashCode(x, 0, 2);
		}
	}

}