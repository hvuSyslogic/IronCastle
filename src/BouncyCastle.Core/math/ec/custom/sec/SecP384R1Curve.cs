using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecP384R1Curve : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"));

		private const int SecP384R1_DEFAULT_COORDS = COORD_JACOBIAN;

		protected internal SecP384R1Point infinity;

		public SecP384R1Curve() : base(q)
		{

			this.infinity = new SecP384R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")));
			this.order = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"));
			this.cofactor = BigInteger.valueOf(1);

			this.coord = SecP384R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecP384R1Curve();
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
			return new SecP384R1FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecP384R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecP384R1Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_INTS = 12;


			uint[] table = new uint[len * FE_INTS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat.copy(FE_INTS, ((SecP384R1FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat.copy(FE_INTS, ((SecP384R1FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new SecP384R1LookupTable(this, len, FE_INTS, table);
		}

		public class SecP384R1LookupTable : ECLookupTable
		{
			private readonly SecP384R1Curve outerInstance;

			private int len;
			private int FE_INTS;
			private uint[] table;

			public SecP384R1LookupTable(SecP384R1Curve outerInstance, int len, int FE_INTS, uint[] table)
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
				uint[] x = Nat.create(FE_INTS), y = Nat.create(FE_INTS);
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

				return outerInstance.createRawPoint(new SecP384R1FieldElement(x), new SecP384R1FieldElement(y), false);
			}
		}
	}

}