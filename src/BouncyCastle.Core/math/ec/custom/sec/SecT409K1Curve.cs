using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT409K1Curve : ECCurve.AbstractF2m
	{
		private const int SecT409K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT409K1Point infinity;

		public SecT409K1Curve() : base(409, 87, 0, 0)
		{

			this.infinity = new SecT409K1Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(0));
			this.b = fromBigInteger(BigInteger.valueOf(1));
			this.order = new BigInteger(1, Hex.decode("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF"));
			this.cofactor = BigInteger.valueOf(4);

			this.coord = SecT409K1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT409K1Curve();
		}

		public override bool supportsCoordinateSystem(int coord)
		{
			switch (coord)
			{
			case COORD_LAMBDA_PROJECTIVE:
				return true;
			default:
				return false;
			}
		}

		public override ECMultiplier createDefaultMultiplier()
		{
			return new WTauNafMultiplier();
		}

		public override int getFieldSize()
		{
			return 409;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT409FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT409K1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT409K1Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}

		public override bool isKoblitz()
		{
			return true;
		}

		public virtual int getM()
		{
			return 409;
		}

		public virtual bool isTrinomial()
		{
			return true;
		}

		public virtual int getK1()
		{
			return 87;
		}

		public virtual int getK2()
		{
			return 0;
		}

		public virtual int getK3()
		{
			return 0;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_LONGS = 7;


			ulong[] table = new ulong[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat448.copy64(((SecT409FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat448.copy64(((SecT409FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT409K1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT409K1CurveLookupTable : ECLookupTable
		{
			private readonly SecT409K1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT409K1CurveLookupTable(SecT409K1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
			{
				this.outerInstance = outerInstance;
				this.len = len;
				this.FE_LONGS = FE_LONGS;
				this.table = table;
			}

			public int getSize()
			{
				return len;
			}

			public ECPoint lookup(int index)
			{
				ulong[] x = Nat448.create64(), y = Nat448.create64();
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					ulong MASK = (ulong)(((i ^ index) - 1) >> 31);

					for (int j = 0; j < FE_LONGS; ++j)
					{
						x[j] ^= table[pos + j] & MASK;
						y[j] ^= table[pos + FE_LONGS + j] & MASK;
					}

					pos += (FE_LONGS * 2);
				}

				return outerInstance.createRawPoint(new SecT409FieldElement(x), new SecT409FieldElement(y), false);
			}
		}
	}

}