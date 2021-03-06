﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

		
	
	public class SecT113R2Curve : ECCurve.AbstractF2m
	{
		private const int SecT113R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT113R2Point infinity;

		public SecT113R2Curve() : base(113, 9, 0, 0)
		{

			this.infinity = new SecT113R2Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("00689918DBEC7E5A0DD6DFC0AA55C7")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("0095E9A9EC9B297BD4BF36E059184F")));
			this.order = new BigInteger(1, Hex.decode("010000000000000108789B2496AF93"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT113R2_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT113R2Curve();
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
			return new SecT113R2Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT113R2Point(this, x, y, zs, withCompression);
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

			return new SecT113R2CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT113R2CurveLookupTable : ECLookupTable
		{
			private readonly SecT113R2Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT113R2CurveLookupTable(SecT113R2Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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