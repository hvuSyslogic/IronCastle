using org.bouncycastle.Port.java.lang;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{
	public class SecP128R1Point : ECPoint.AbstractFp
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
		public SecP128R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) : this(curve, x, y, false)
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
		public SecP128R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression) : base(curve, x, y)
		{

			if ((x == null) != (y == null))
			{
				throw new IllegalArgumentException("Exactly one of the field elements is null");
			}

			this.withCompression = withCompression;
		}

		public SecP128R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression) : base(curve, x, y, zs)
		{

			this.withCompression = withCompression;
		}

		public override ECPoint detach()
		{
			return new SecP128R1Point(null, getAffineXCoord(), getAffineYCoord());
		}

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

			SecP128R1FieldElement X1 = (SecP128R1FieldElement)this.x, Y1 = (SecP128R1FieldElement)this.y;
			SecP128R1FieldElement X2 = (SecP128R1FieldElement)b.getXCoord(), Y2 = (SecP128R1FieldElement)b.getYCoord();

			SecP128R1FieldElement Z1 = (SecP128R1FieldElement)this.zs[0];
			SecP128R1FieldElement Z2 = (SecP128R1FieldElement)b.getZCoord(0);

			uint c;
			uint[] tt1 = Nat128.createExt();
			uint[] t2 = Nat128.create();
			uint[] t3 = Nat128.create();
			uint[] t4 = Nat128.create();

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
				SecP128R1Field.square(Z1.x, S2);

				U2 = t2;
				SecP128R1Field.multiply(S2, X2.x, U2);

				SecP128R1Field.multiply(S2, Z1.x, S2);
				SecP128R1Field.multiply(S2, Y2.x, S2);
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
				SecP128R1Field.square(Z2.x, S1);

				U1 = tt1;
				SecP128R1Field.multiply(S1, X1.x, U1);

				SecP128R1Field.multiply(S1, Z2.x, S1);
				SecP128R1Field.multiply(S1, Y1.x, S1);
			}

			uint[] H = Nat128.create();
			SecP128R1Field.subtract(U1, U2, H);

			uint[] R = t2;
			SecP128R1Field.subtract(S1, S2, R);

			// Check if b == this or b == -this
			if (Nat128.isZero(H))
			{
				if (Nat128.isZero(R))
				{
					// this == b, i.e. this must be doubled
					return this.twice();
				}

				// this == -b, i.e. the result is the point at infinity
				return curve.getInfinity();
			}

			uint[] HSquared = t3;
			SecP128R1Field.square(H, HSquared);

			uint[] G = Nat128.create();
			SecP128R1Field.multiply(HSquared, H, G);

			uint[] V = t3;
			SecP128R1Field.multiply(HSquared, U1, V);

			SecP128R1Field.negate(G, G);
			Nat128.mul(S1, G, tt1);

			c = Nat128.addBothTo(V, V, G);
			SecP128R1Field.reduce32(c, G);

			SecP128R1FieldElement X3 = new SecP128R1FieldElement(t4);
			SecP128R1Field.square(R, X3.x);
			SecP128R1Field.subtract(X3.x, G, X3.x);

			SecP128R1FieldElement Y3 = new SecP128R1FieldElement(G);
			SecP128R1Field.subtract(V, X3.x, Y3.x);
			SecP128R1Field.multiplyAddToExt(Y3.x, R, tt1);
			SecP128R1Field.reduce(tt1, Y3.x);

			SecP128R1FieldElement Z3 = new SecP128R1FieldElement(H);
			if (!Z1IsOne)
			{
				SecP128R1Field.multiply(Z3.x, Z1.x, Z3.x);
			}
			if (!Z2IsOne)
			{
				SecP128R1Field.multiply(Z3.x, Z2.x, Z3.x);
			}

			ECFieldElement[] zs = new ECFieldElement[]{Z3};

			return new SecP128R1Point(curve, X3, Y3, zs, this.withCompression);
		}

		public override ECPoint twice()
		{
			if (this.isInfinity())
			{
				return this;
			}

			ECCurve curve = this.getCurve();

			SecP128R1FieldElement Y1 = (SecP128R1FieldElement)this.y;
			if (Y1.isZero())
			{
				return curve.getInfinity();
			}

			SecP128R1FieldElement X1 = (SecP128R1FieldElement)this.x, Z1 = (SecP128R1FieldElement)this.zs[0];

			uint c;
			uint[] t1 = Nat128.create();
			uint[] t2 = Nat128.create();

			uint[] Y1Squared = Nat128.create();
			SecP128R1Field.square(Y1.x, Y1Squared);

			uint[] T = Nat128.create();
			SecP128R1Field.square(Y1Squared, T);

			bool Z1IsOne = Z1.isOne();

			uint[] Z1Squared = Z1.x;
			if (!Z1IsOne)
			{
				Z1Squared = t2;
				SecP128R1Field.square(Z1.x, Z1Squared);
			}

			SecP128R1Field.subtract(X1.x, Z1Squared, t1);

			uint[] M = t2;
			SecP128R1Field.add(X1.x, Z1Squared, M);
			SecP128R1Field.multiply(M, t1, M);
			c = Nat128.addBothTo(M, M, M);
			SecP128R1Field.reduce32(c, M);

			uint[] S = Y1Squared;
			SecP128R1Field.multiply(Y1Squared, X1.x, S);
			c = Nat.shiftUpBits(4, S, 2, 0);
			SecP128R1Field.reduce32(c, S);

			c = Nat.shiftUpBits(4, T, 3, 0, t1);
			SecP128R1Field.reduce32(c, t1);

			SecP128R1FieldElement X3 = new SecP128R1FieldElement(T);
			SecP128R1Field.square(M, X3.x);
			SecP128R1Field.subtract(X3.x, S, X3.x);
			SecP128R1Field.subtract(X3.x, S, X3.x);

			SecP128R1FieldElement Y3 = new SecP128R1FieldElement(S);
			SecP128R1Field.subtract(S, X3.x, Y3.x);
			SecP128R1Field.multiply(Y3.x, M, Y3.x);
			SecP128R1Field.subtract(Y3.x, t1, Y3.x);

			SecP128R1FieldElement Z3 = new SecP128R1FieldElement(M);
			SecP128R1Field.twice(Y1.x, Z3.x);
			if (!Z1IsOne)
			{
				SecP128R1Field.multiply(Z3.x, Z1.x, Z3.x);
			}

			return new SecP128R1Point(curve, X3, Y3, new ECFieldElement[]{Z3}, this.withCompression);
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

			return new SecP128R1Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
		}
	}

}