﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	
	public class SecP160R1Curve : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"));

		private const int SecP160R1_DEFAULT_COORDS = COORD_JACOBIAN;

		protected internal SecP160R1Point infinity;

		public SecP160R1Curve() : base(q)
		{

			this.infinity = new SecP160R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45")));
			this.order = new BigInteger(1, Hex.decode("0100000000000000000001F4C8F927AED3CA752257"));
			this.cofactor = BigInteger.valueOf(1);

			this.coord = SecP160R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecP160R1Curve();
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
			return new SecP160R1FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecP160R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecP160R1Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_INTS = 5;


			uint[] table = new uint[len * FE_INTS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat160.copy(((SecP160R1FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat160.copy(((SecP160R1FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new SecP160R1LookupTable(this, len, FE_INTS, table);
		}

		public class SecP160R1LookupTable : ECLookupTable
		{
			private readonly SecP160R1Curve outerInstance;

			private int len;
			private int FE_INTS;
			private uint[] table;

			public SecP160R1LookupTable(SecP160R1Curve outerInstance, int len, int FE_INTS, uint[] table)
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
				uint[] x = Nat160.create(), y = Nat160.create();
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					uint MASK = (uint) (((i ^ index) - 1) >> 31);

					for (int j = 0; j < FE_INTS; ++j)
					{
						x[j] ^= table[pos + j] & MASK;
						y[j] ^= table[pos + FE_INTS + j] & MASK;
					}

					pos += (FE_INTS * 2);
				}

				return outerInstance.createRawPoint(new SecP160R1FieldElement(x), new SecP160R1FieldElement(y), false);
			}
		}
	}

}