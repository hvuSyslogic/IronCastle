﻿using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Nat160 = org.bouncycastle.math.raw.Nat160;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecP160R2Curve : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73"));

		private const int SecP160R2_DEFAULT_COORDS = COORD_JACOBIAN;

		protected internal SecP160R2Point infinity;

		public SecP160R2Curve() : base(q)
		{

			this.infinity = new SecP160R2Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("B4E134D3FB59EB8BAB57274904664D5AF50388BA")));
			this.order = new BigInteger(1, Hex.decode("0100000000000000000000351EE786A818F3A1A16B"));
			this.cofactor = BigInteger.valueOf(1);

			this.coord = SecP160R2_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecP160R2Curve();
		}

		public override bool supportsCoordinateSystem(int coord)
		{
			switch (coord)
			{
			case COORD_JACOBIAN:
				return true;
			default:
				return false;
			}
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		public override int getFieldSize()
		{
			return q.bitLength();
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecP160R2FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecP160R2Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecP160R2Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.math.ec.ECLookupTable createCacheSafeLookupTable(org.bouncycastle.math.ec.ECPoint[] points, int off, final int len)
		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_INTS = 5;

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int[] table = new int[len * FE_INTS * 2];
			int[] table = new int[len * FE_INTS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat160.copy(((SecP160R2FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat160.copy(((SecP160R2FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_INTS, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly SecP160R2Curve outerInstance;

			private int len;
			private int FE_INTS;
			private int[] table;

			public ECLookupTableAnonymousInnerClass(SecP160R2Curve outerInstance, int len, int FE_INTS, int[] table)
			{
				this.outerInstance = outerInstance;
				this.len = len;
				this.FE_INTS = FE_INTS;
				this.table = table;
			}

			public int getSize()
			{
				return len;
			}

			public ECPoint lookup(int index)
			{
				int[] x = Nat160.create(), y = Nat160.create();
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					int MASK = ((i ^ index) - 1) >> 31;

					for (int j = 0; j < FE_INTS; ++j)
					{
						x[j] ^= table[pos + j] & MASK;
						y[j] ^= table[pos + FE_INTS + j] & MASK;
					}

					pos += (FE_INTS * 2);
				}

				return outerInstance.createRawPoint(new SecP160R2FieldElement(x), new SecP160R2FieldElement(y), false);
			}
		}
	}

}