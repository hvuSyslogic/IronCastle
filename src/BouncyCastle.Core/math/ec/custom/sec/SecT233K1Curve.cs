﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

		
	
	public class SecT233K1Curve : ECCurve.AbstractF2m
	{
		private const int SecT233K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT233K1Point infinity;

		public SecT233K1Curve() : base(233, 74, 0, 0)
		{

			this.infinity = new SecT233K1Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(0));
			this.b = fromBigInteger(BigInteger.valueOf(1));
			this.order = new BigInteger(1, Hex.decode("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF"));
			this.cofactor = BigInteger.valueOf(4);

			this.coord = SecT233K1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT233K1Curve();
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
			return 233;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT233FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT233K1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT233K1Point(this, x, y, zs, withCompression);
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
			return 233;
		}

		public virtual bool isTrinomial()
		{
			return true;
		}

		public virtual int getK1()
		{
			return 74;
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


			ulong[] table = new ulong[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat256.copy64(((SecT233FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat256.copy64(((SecT233FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT233K1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT233K1CurveLookupTable : ECLookupTable
		{
			private readonly SecT233K1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT233K1CurveLookupTable(SecT233K1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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
				ulong[] x = Nat256.create64(), y = Nat256.create64();
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

				return outerInstance.createRawPoint(new SecT233FieldElement(x), new SecT233FieldElement(y), false);
			}
		}
	}

}