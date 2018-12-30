using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecP160K1Curve : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = SecP160R2Curve.q;

		private const int SECP160K1_DEFAULT_COORDS = COORD_JACOBIAN;

		protected internal SecP160K1Point infinity;

		public SecP160K1Curve() : base(q)
		{

			this.infinity = new SecP160K1Point(this, null, null);

			this.a = fromBigInteger(ECConstants_Fields.ZERO);
			this.b = fromBigInteger(BigInteger.valueOf(7));
			this.order = new BigInteger(1, Hex.decode("0100000000000000000001B8FA16DFAB9ACA16B6B3"));
			this.cofactor = BigInteger.valueOf(1);
			this.coord = SECP160K1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecP160K1Curve();
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
			return new SecP160K1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecP160K1Point(this, x, y, zs, withCompression);
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
					Nat160.copy(((SecP160R2FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat160.copy(((SecP160R2FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new SecP160K1LookupTable(this, len, FE_INTS, table);
		}

		public class SecP160K1LookupTable : ECLookupTable
		{
			private readonly SecP160K1Curve outerInstance;

			private int len;
			private int FE_INTS;
			private uint[] table;

			public SecP160K1LookupTable(SecP160K1Curve outerInstance, int len, int FE_INTS, uint[] table)
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

				return outerInstance.createRawPoint(new SecP160R2FieldElement(x), new SecP160R2FieldElement(y), false);
			}
		}
	}

}