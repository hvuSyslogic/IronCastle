using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT193R1Curve : ECCurve.AbstractF2m
	{
		private const int SecT193R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT193R1Point infinity;

		public SecT193R1Curve() : base(193, 15, 0, 0)
		{

			this.infinity = new SecT193R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814")));
			this.order = new BigInteger(1, Hex.decode("01000000000000000000000000C7F34A778F443ACC920EBA49"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT193R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT193R1Curve();
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
			return 193;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT193FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT193R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT193R1Point(this, x, y, zs, withCompression);
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
			return 193;
		}

		public virtual bool isTrinomial()
		{
			return true;
		}

		public virtual int getK1()
		{
			return 15;
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
			const int FE_LONGS = 4;


			long[] table = new long[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat256.copy64(((SecT193FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat256.copy64(((SecT193FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_LONGS, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly SecT193R1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private long[] table;

			public ECLookupTableAnonymousInnerClass(SecT193R1Curve outerInstance, int len, int FE_LONGS, long[] table)
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
				long[] x = Nat256.create64(), y = Nat256.create64();
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					long MASK = ((i ^ index) - 1) >> 31;

					for (int j = 0; j < FE_LONGS; ++j)
					{
						x[j] ^= table[pos + j] & MASK;
						y[j] ^= table[pos + FE_LONGS + j] & MASK;
					}

					pos += (FE_LONGS * 2);
				}

				return outerInstance.createRawPoint(new SecT193FieldElement(x), new SecT193FieldElement(y), false);
			}
		}
	}

}