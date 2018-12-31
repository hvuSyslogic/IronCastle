using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	using Arrays = org.bouncycastle.util.Arrays;

	public class SecT239FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal ulong[] x;

		public SecT239FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 239)
			{
				throw new IllegalArgumentException("x value invalid for SecT239FieldElement");
			}

			this.x = SecT239Field.fromBigInteger(x);
		}

		public SecT239FieldElement()
		{
			this.x = Nat256.create64();
		}

		public SecT239FieldElement(ulong[] x)
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
			return "SecT239Field";
		}

		public override int getFieldSize()
		{
			return 239;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			ulong[] z = Nat256.create64();
			SecT239Field.add(x, ((SecT239FieldElement)b).x, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			ulong[] z = Nat256.create64();
			SecT239Field.addOne(x, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			ulong[] z = Nat256.create64();
			SecT239Field.multiply(x, ((SecT239FieldElement)b).x, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x, bx = ((SecT239FieldElement)b).x;
			ulong[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

			ulong[] tt = Nat256.createExt64();
			SecT239Field.multiplyAddToExt(ax, bx, tt);
			SecT239Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat256.create64();
			SecT239Field.reduce(tt, z);
			return new SecT239FieldElement(z);
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
			ulong[] z = Nat256.create64();
			SecT239Field.square(x, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x;
			ulong[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

			ulong[] tt = Nat256.createExt64();
			SecT239Field.squareAddToExt(ax, tt);
			SecT239Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat256.create64();
			SecT239Field.reduce(tt, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			ulong[] z = Nat256.create64();
			SecT239Field.squareN(x, pow, z);
			return new SecT239FieldElement(z);
		}

		public override uint trace()
		{
			return SecT239Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			ulong[] z = Nat256.create64();
			SecT239Field.invert(x, z);
			return new SecT239FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			ulong[] z = Nat256.create64();
			SecT239Field.sqrt(x, z);
			return new SecT239FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.TPB;
		}

		public virtual int getM()
		{
			return 239;
		}

		public virtual int getK1()
		{
			return 158;
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

			if (!(other is SecT239FieldElement))
			{
				return false;
			}

			SecT239FieldElement o = (SecT239FieldElement)other;
			return Nat256.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 23900158 ^ Arrays.GetHashCode(x, 0, 4);
		}
	}

}