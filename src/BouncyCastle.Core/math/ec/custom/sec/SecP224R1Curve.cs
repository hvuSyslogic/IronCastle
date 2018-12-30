using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecP224R1Curve : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"));

		private const int SecP224R1_DEFAULT_COORDS = COORD_JACOBIAN;

		protected internal SecP224R1Point infinity;

		public SecP224R1Curve() : base(q)
		{

			this.infinity = new SecP224R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4")));
			this.order = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"));
			this.cofactor = BigInteger.valueOf(1);

			this.coord = SecP224R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecP224R1Curve();
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
			return new SecP224R1FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecP224R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecP224R1Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_INTS = 7;


			uint[] table = new uint[len * FE_INTS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat224.copy(((SecP224R1FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat224.copy(((SecP224R1FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new SecP224R1LookupTable(this, len, FE_INTS, table);
		}

        private class SecP224R1LookupTable : ECLookupTable
		{
			private readonly SecP224R1Curve outerInstance;

			private int len;
			private int FE_INTS;
			private uint[] table;

			public SecP224R1LookupTable(SecP224R1Curve outerInstance, int len, int FE_INTS, uint[] table)
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
				uint[] x = Nat224.create(), y = Nat224.create();
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

				return outerInstance.createRawPoint(new SecP224R1FieldElement(x), new SecP224R1FieldElement(y), false);
			}
		}
	}

}