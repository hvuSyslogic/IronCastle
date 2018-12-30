using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

	using AbstractF2m = org.bouncycastle.math.ec.ECCurve.AbstractF2m;
	using Nat192 = org.bouncycastle.math.raw.Nat192;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class SecT163R2Curve : ECCurve.AbstractF2m
	{
		private const int SecT163R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT163R2Point infinity;

		public SecT163R2Curve() : base(163, 3, 6, 7)
		{

			this.infinity = new SecT163R2Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(1));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("020A601907B8C953CA1481EB10512F78744A3205FD")));
			this.order = new BigInteger(1, Hex.decode("040000000000000000000292FE77E70C12A4234C33"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT163R2_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT163R2Curve();
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
			return 163;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT163FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT163R2Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT163R2Point(this, x, y, zs, withCompression);
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
			return 163;
		}

		public virtual bool isTrinomial()
		{
			return false;
		}

		public virtual int getK1()
		{
			return 3;
		}

		public virtual int getK2()
		{
			return 6;
		}

		public virtual int getK3()
		{
			return 7;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_LONGS = 3;


			long[] table = new long[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat192.copy64(((SecT163FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat192.copy64(((SecT163FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_LONGS, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly SecT163R2Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private long[] table;

			public ECLookupTableAnonymousInnerClass(SecT163R2Curve outerInstance, int len, int FE_LONGS, long[] table)
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
				long[] x = Nat192.create64(), y = Nat192.create64();
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

				return outerInstance.createRawPoint(new SecT163FieldElement(x), new SecT163FieldElement(y), false);
			}
		}
	}

}