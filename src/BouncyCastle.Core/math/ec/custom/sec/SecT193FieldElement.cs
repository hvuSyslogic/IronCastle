﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	public class SecT193FieldElement : ECFieldElement.AbstractF2m
	{
		protected internal ulong[] x;

		public SecT193FieldElement(BigInteger x)
		{
			if (x == null || x.signum() < 0 || x.bitLength() > 193)
			{
				throw new IllegalArgumentException("x value invalid for SecT193FieldElement");
			}

			this.x = SecT193Field.fromBigInteger(x);
		}

		public SecT193FieldElement()
		{
			this.x = Nat256.create64();
		}

		public SecT193FieldElement(ulong[] x)
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
			return "SecT193Field";
		}

		public override int getFieldSize()
		{
			return 193;
		}

		public override ECFieldElement add(ECFieldElement b)
		{
			ulong[] z = Nat256.create64();
			SecT193Field.add(x, ((SecT193FieldElement)b).x, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement addOne()
		{
			ulong[] z = Nat256.create64();
			SecT193Field.addOne(x, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement subtract(ECFieldElement b)
		{
			// Addition and subtraction are the same in F2m
			return add(b);
		}

		public override ECFieldElement multiply(ECFieldElement b)
		{
			ulong[] z = Nat256.create64();
			SecT193Field.multiply(x, ((SecT193FieldElement)b).x, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			return multiplyPlusProduct(b, x, y);
		}

		public override ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x, bx = ((SecT193FieldElement)b).x;
			ulong[] xx = ((SecT193FieldElement)x).x, yx = ((SecT193FieldElement)y).x;

			ulong[] tt = Nat256.createExt64();
			SecT193Field.multiplyAddToExt(ax, bx, tt);
			SecT193Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat256.create64();
			SecT193Field.reduce(tt, z);
			return new SecT193FieldElement(z);
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
			SecT193Field.square(x, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
		{
			return squarePlusProduct(x, y);
		}

		public override ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
		{
			ulong[] ax = this.x;
			ulong[] xx = ((SecT193FieldElement)x).x, yx = ((SecT193FieldElement)y).x;

			ulong[] tt = Nat256.createExt64();
			SecT193Field.squareAddToExt(ax, tt);
			SecT193Field.multiplyAddToExt(xx, yx, tt);

			ulong[] z = Nat256.create64();
			SecT193Field.reduce(tt, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement squarePow(int pow)
		{
			if (pow < 1)
			{
				return this;
			}

			ulong[] z = Nat256.create64();
			SecT193Field.squareN(x, pow, z);
			return new SecT193FieldElement(z);
		}

		public override uint trace()
		{
			return SecT193Field.trace(x);
		}

		public override ECFieldElement invert()
		{
			ulong[] z = Nat256.create64();
			SecT193Field.invert(x, z);
			return new SecT193FieldElement(z);
		}

		public override ECFieldElement sqrt()
		{
			ulong[] z = Nat256.create64();
			SecT193Field.sqrt(x, z);
			return new SecT193FieldElement(z);
		}

		public virtual int getRepresentation()
		{
			return ECFieldElement.F2m.TPB;
		}

		public virtual int getM()
		{
			return 193;
		}

		public virtual int getK1()
		{
			return 15;
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

			if (!(other is SecT193FieldElement))
			{
				return false;
			}

			SecT193FieldElement o = (SecT193FieldElement)other;
			return Nat256.eq64(x, o.x);
		}

		public override int GetHashCode()
		{
			return 1930015 ^ Arrays.GetHashCode(x, 0, 4);
		}
	}

}