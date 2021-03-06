﻿using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP192K1Point : ECPoint.AbstractFp
	{
		/// <summary>
		/// Create a point which encodes with point compression.
		/// </summary>
		/// <param name="curve">
		///            the curve to use </param>
		/// <param name="x">
		///            affine x co-ordinate </param>
		/// <param name="y">
		///            affine y co-ordinate
		/// </param>
		/// @deprecated Use ECCurve.createPoint to construct points 
		public SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) : this(curve, x, y, false)
		{
		}

		/// <summary>
		/// Create a point that encodes with or without point compresion.
		/// </summary>
		/// <param name="curve">
		///            the curve to use </param>
		/// <param name="x">
		///            affine x co-ordinate </param>
		/// <param name="y">
		///            affine y co-ordinate </param>
		/// <param name="withCompression">
		///            if true encode with point compression
		/// </param>
		/// @deprecated per-point compression property will be removed, refer
		///             <seealso cref="#getEncoded(boolean)"/> 
		public SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression) : base(curve, x, y)
		{

			if ((x == null) != (y == null))
			{
				throw new IllegalArgumentException("Exactly one of the field elements is null");
			}

			this.withCompression = withCompression;
		}

		public SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression) : base(curve, x, y, zs)
		{

			this.withCompression = withCompression;
		}

		public override ECPoint detach()
		{
			return new SecP192K1Point(null, getAffineXCoord(), getAffineYCoord());
		}

		// B.3 pg 62
		public override ECPoint add(ECPoint b)
		{
			if (this.isInfinity())
			{
				return b;
			}
			if (b.isInfinity())
			{
				return this;
			}
			if (this == b)
			{
				return twice();
			}

			ECCurve curve = this.getCurve();

			SecP192K1FieldElement X1 = (SecP192K1FieldElement)this.x, Y1 = (SecP192K1FieldElement)this.y;
			SecP192K1FieldElement X2 = (SecP192K1FieldElement)b.getXCoord(), Y2 = (SecP192K1FieldElement)b.getYCoord();

			SecP192K1FieldElement Z1 = (SecP192K1FieldElement)this.zs[0];
			SecP192K1FieldElement Z2 = (SecP192K1FieldElement)b.getZCoord(0);

			uint c;
			uint[] tt1 = Nat192.createExt();
			uint[] t2 = Nat192.create();
			uint[] t3 = Nat192.create();
			uint[] t4 = Nat192.create();
            
			bool Z1IsOne = Z1.isOne();
			uint[] U2, S2;
			if (Z1IsOne)
			{
				U2 = X2.x;
				S2 = Y2.x;
			}
			else
			{
				S2 = t3;
				SecP192K1Field.square(Z1.x, S2);

				U2 = t2;
				SecP192K1Field.multiply(S2, X2.x, U2);

				SecP192K1Field.multiply(S2, Z1.x, S2);
				SecP192K1Field.multiply(S2, Y2.x, S2);
			}

			bool Z2IsOne = Z2.isOne();
			uint[] U1, S1;
			if (Z2IsOne)
			{
				U1 = X1.x;
				S1 = Y1.x;
			}
			else
			{
				S1 = t4;
				SecP192K1Field.square(Z2.x, S1);

				U1 = tt1;
				SecP192K1Field.multiply(S1, X1.x, U1);

				SecP192K1Field.multiply(S1, Z2.x, S1);
				SecP192K1Field.multiply(S1, Y1.x, S1);
			}

			uint[] H = Nat192.create();
			SecP192K1Field.subtract(U1, U2, H);

			uint[] R = t2;
			SecP192K1Field.subtract(S1, S2, R);

			// Check if b == this or b == -this
			if (Nat192.isZero(H))
			{
				if (Nat192.isZero(R))
				{
					// this == b, i.e. this must be doubled
					return this.twice();
				}

				// this == -b, i.e. the result is the point at infinity
				return curve.getInfinity();
			}

			uint[] HSquared = t3;
			SecP192K1Field.square(H, HSquared);

			uint[] G = Nat192.create();
			SecP192K1Field.multiply(HSquared, H, G);

			uint[] V = t3;
			SecP192K1Field.multiply(HSquared, U1, V);

			SecP192K1Field.negate(G, G);
			Nat192.mul(S1, G, tt1);

			c = Nat192.addBothTo(V, V, G);
			SecP192K1Field.reduce32(c, G);

			SecP192K1FieldElement X3 = new SecP192K1FieldElement(t4);
			SecP192K1Field.square(R, X3.x);
			SecP192K1Field.subtract(X3.x, G, X3.x);

			SecP192K1FieldElement Y3 = new SecP192K1FieldElement(G);
			SecP192K1Field.subtract(V, X3.x, Y3.x);
			SecP192K1Field.multiplyAddToExt(Y3.x, R, tt1);
			SecP192K1Field.reduce(tt1, Y3.x);

			SecP192K1FieldElement Z3 = new SecP192K1FieldElement(H);
			if (!Z1IsOne)
			{
				SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
			}
			if (!Z2IsOne)
			{
				SecP192K1Field.multiply(Z3.x, Z2.x, Z3.x);
			}

			ECFieldElement[] zs = new ECFieldElement[] {Z3};

			return new SecP192K1Point(curve, X3, Y3, zs, this.withCompression);
		}

		// B.3 pg 62
		public override ECPoint twice()
		{
			if (this.isInfinity())
			{
				return this;
			}

			ECCurve curve = this.getCurve();

			SecP192K1FieldElement Y1 = (SecP192K1FieldElement)this.y;
			if (Y1.isZero())
			{
				return curve.getInfinity();
			}

			SecP192K1FieldElement X1 = (SecP192K1FieldElement)this.x, Z1 = (SecP192K1FieldElement)this.zs[0];

			uint c;

			uint[] Y1Squared = Nat192.create();
			SecP192K1Field.square(Y1.x, Y1Squared);

			uint[] T = Nat192.create();
			SecP192K1Field.square(Y1Squared, T);

			uint[] M = Nat192.create();
			SecP192K1Field.square(X1.x, M);
			c = Nat192.addBothTo(M, M, M);
			SecP192K1Field.reduce32(c, M);

			uint[] S = Y1Squared;
			SecP192K1Field.multiply(Y1Squared, X1.x, S);
			c = Nat.shiftUpBits(6, S, 2, 0);
			SecP192K1Field.reduce32(c, S);

			uint[] t1 = Nat192.create();
			c = Nat.shiftUpBits(6, T, 3, 0, t1);
			SecP192K1Field.reduce32(c, t1);

			SecP192K1FieldElement X3 = new SecP192K1FieldElement(T);
			SecP192K1Field.square(M, X3.x);
			SecP192K1Field.subtract(X3.x, S, X3.x);
			SecP192K1Field.subtract(X3.x, S, X3.x);

			SecP192K1FieldElement Y3 = new SecP192K1FieldElement(S);
			SecP192K1Field.subtract(S, X3.x, Y3.x);
			SecP192K1Field.multiply(Y3.x, M, Y3.x);
			SecP192K1Field.subtract(Y3.x, t1, Y3.x);

			SecP192K1FieldElement Z3 = new SecP192K1FieldElement(M);
			SecP192K1Field.twice(Y1.x, Z3.x);
			if (!Z1.isOne())
			{
				SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
			}

			return new SecP192K1Point(curve, X3, Y3, new ECFieldElement[] {Z3}, this.withCompression);
		}

		public override ECPoint twicePlus(ECPoint b)
		{
			if (this == b)
			{
				return threeTimes();
			}
			if (this.isInfinity())
			{
				return b;
			}
			if (b.isInfinity())
			{
				return twice();
			}

			ECFieldElement Y1 = this.y;
			if (Y1.isZero())
			{
				return b;
			}

			return twice().add(b);
		}

		public override ECPoint threeTimes()
		{
			if (this.isInfinity() || this.y.isZero())
			{
				return this;
			}

			// NOTE: Be careful about recursions between twicePlus and threeTimes
			return twice().add(this);
		}

		public override ECPoint negate()
		{
			if (this.isInfinity())
			{
				return this;
			}

			return new SecP192K1Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
		}
	}

}