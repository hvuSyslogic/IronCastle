using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT571K1Curve : ECCurve.AbstractF2m
	{
		private const int SecT571K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT571K1Point infinity;

		public SecT571K1Curve() : base(571, 2, 5, 10)
		{

			this.infinity = new SecT571K1Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(0));
			this.b = fromBigInteger(BigInteger.valueOf(1));
			this.order = new BigInteger(1, Hex.decode("020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001"));
			this.cofactor = BigInteger.valueOf(4);

			this.coord = SecT571K1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT571K1Curve();
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
			return 571;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT571FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT571K1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT571K1Point(this, x, y, zs, withCompression);
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
			return 571;
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
			return 5;
		}

		public virtual int getK3()
		{
			return 10;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_LONGS = 9;


			long[] table = new long[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat576.copy64(((SecT571FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat576.copy64(((SecT571FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_LONGS, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly SecT571K1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private long[] table;

			public ECLookupTableAnonymousInnerClass(SecT571K1Curve outerInstance, int len, int FE_LONGS, long[] table)
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
				long[] x = Nat576.create64(), y = Nat576.create64();
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

				return outerInstance.createRawPoint(new SecT571FieldElement(x), new SecT571FieldElement(y), false);
			}
		}
	}

}