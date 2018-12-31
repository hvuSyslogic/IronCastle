using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT131R2Curve : ECCurve.AbstractF2m
	{
		private const int SecT131R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT131R2Point infinity;

		public SecT131R2Curve() : base(131, 2, 3, 8)
		{

			this.infinity = new SecT131R2Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("03E5A88919D7CAFCBF415F07C2176573B2")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("04B8266A46C55657AC734CE38F018F2192")));
			this.order = new BigInteger(1, Hex.decode("0400000000000000016954A233049BA98F"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT131R2_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT131R2Curve();
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

		public override int getFieldSize()
		{
			return 131;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT131FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT131R2Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT131R2Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}

		public override bool isKoblitz()
		{
			return false;
		}

		public virtual int getM()
		{
			return 131;
		}

		public virtual bool isTrinomial()
		{
			return false;
		}

		public virtual int getK1()
		{
			return 2;
		}

		public virtual int getK2()
		{
			return 3;
		}

		public virtual int getK3()
		{
			return 8;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_LONGS = 3;


			ulong[] table = new ulong[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat192.copy64(((SecT131FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat192.copy64(((SecT131FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT131R2CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT131R2CurveLookupTable : ECLookupTable
		{
			private readonly SecT131R2Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT131R2CurveLookupTable(SecT131R2Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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
				ulong[] x = Nat192.create64(), y = Nat192.create64();
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

				return outerInstance.createRawPoint(new SecT131FieldElement(x), new SecT131FieldElement(y), false);
			}
		}
	}

}