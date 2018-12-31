using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT163FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal ulong[] x;

		public SecT163FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 163)
			{
				throw new IllegalArgumentException("x value invalid for SecT163FieldElement");
			}

			this.x = SecT163Field.fromBigInteger(x);
		}

		public SecT163FieldElement()
		{
			this.x = Nat192.create64();
		}

		public SecT163FieldElement(ulong[] x)
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
			return "SecT163Field";
		}

		public override int getFieldSize()
		{
			return 163;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			ulong[] z = Nat192.create64();
			SecT163Field.add(x, ((SecT163FieldElement)b).x, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			ulong[] z = Nat192.create64();
			SecT163Field.addOne(x, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			ulong[] z = Nat192.create64();
			SecT163Field.multiply(x, ((SecT163FieldElement)b).x, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x, bx = ((SecT163FieldElement)b).x;
			ulong[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

			ulong[] tt = Nat192.createExt64();
			SecT163Field.multiplyAddToExt(ax, bx, tt);
			SecT163Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat192.create64();
			SecT163Field.reduce(tt, z);
			return new SecT163FieldElement(z);
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
			ulong[] z = Nat192.create64();
			SecT163Field.square(x, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x;
			ulong[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

			ulong[] tt = Nat192.createExt64();
			SecT163Field.squareAddToExt(ax, tt);
			SecT163Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat192.create64();
			SecT163Field.reduce(tt, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			ulong[] z = Nat192.create64();
			SecT163Field.squareN(x, pow, z);
			return new SecT163FieldElement(z);
		}

		public override uint trace()
		{
			return SecT163Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			ulong[] z = Nat192.create64();
			SecT163Field.invert(x, z);
			return new SecT163FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			ulong[] z = Nat192.create64();
			SecT163Field.sqrt(x, z);
			return new SecT163FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.PPB;
		}

		public virtual int getM()
		{
			return 163;
		}

		public virtual int getK1()
		{
			return 3;
		}

		public virtual int getK2()
		{
			return 6;
		}

		public virtual int getK3()
		{
			return 7;
		}

		public override bool Equals(object other)
		{
			if (other == this)
			{
				return true;
			}

			if (!(other is SecT163FieldElement))
			{
				return false;
			}

			SecT163FieldElement o = (SecT163FieldElement)other;
			return Nat192.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 163763 ^ Arrays.GetHashCode(x, 0, 3);
		}
	}

}