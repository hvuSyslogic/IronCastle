using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT113R1Curve : ECCurve.AbstractF2m
	{
		private const int SecT113R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT113R1Point infinity;

		public SecT113R1Curve() : base(113, 9, 0, 0)
		{

			this.infinity = new SecT113R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("003088250CA6E7C7FE649CE85820F7")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("00E8BEE4D3E2260744188BE0E9C723")));
			this.order = new BigInteger(1, Hex.decode("0100000000000000D9CCEC8A39E56F"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT113R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT113R1Curve();
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
			return 113;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT113FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT113R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT113R1Point(this, x, y, zs, withCompression);
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
			return 113;
		}

		public virtual bool isTrinomial()
		{
			return true;
		}

		public virtual int getK1()
		{
			return 9;
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
			const int FE_LONGS = 2;


			ulong[] table = new ulong[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat128.copy64(((SecT113FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat128.copy64(((SecT113FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT113R1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT113R1CurveLookupTable : ECLookupTable
		{
			private readonly SecT113R1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT113R1CurveLookupTable(SecT113R1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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
				ulong[] x = Nat128.create64(), y = Nat128.create64();
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

				return outerInstance.createRawPoint(new SecT113FieldElement(x), new SecT113FieldElement(y), false);
			}
		}
	}

}