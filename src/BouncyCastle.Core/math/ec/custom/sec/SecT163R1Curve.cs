﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

		
	
	public class SecT163R1Curve : ECCurve.AbstractF2m
	{
		private const int SecT163R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT163R1Point infinity;

		public SecT163R1Curve() : base(163, 3, 6, 7)
		{

			this.infinity = new SecT163R1Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("07B6882CAAEFA84F9554FF8428BD88E246D2782AE2")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9")));
			this.order = new BigInteger(1, Hex.decode("03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT163R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT163R1Curve();
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
			return new SecT163R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT163R1Point(this, x, y, zs, withCompression);
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


			ulong[] table = new ulong[len * FE_LONGS * 2];
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

			return new SecT163R1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT163R1CurveLookupTable : ECLookupTable
		{
			private readonly SecT163R1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT163R1CurveLookupTable(SecT163R1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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

				return outerInstance.createRawPoint(new SecT163FieldElement(x), new SecT163FieldElement(y), false);
			}
		}
	}

}