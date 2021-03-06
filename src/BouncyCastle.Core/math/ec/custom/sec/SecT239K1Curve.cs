﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

		
	
	public class SecT239K1Curve : ECCurve.AbstractF2m
	{
		private const int SecT239K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT239K1Point infinity;

		public SecT239K1Curve() : base(239, 158, 0, 0)
		{

			this.infinity = new SecT239K1Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(0));
			this.b = fromBigInteger(BigInteger.valueOf(1));
			this.order = new BigInteger(1, Hex.decode("2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5"));
			this.cofactor = BigInteger.valueOf(4);

			this.coord = SecT239K1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT239K1Curve();
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
			return 239;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT239FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT239K1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT239K1Point(this, x, y, zs, withCompression);
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
			return 239;
		}

		public virtual bool isTrinomial()
		{
			return true;
		}

		public virtual int getK1()
		{
			return 158;
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
					Nat256.copy64(((SecT239FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat256.copy64(((SecT239FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT239K1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT239K1CurveLookupTable : ECLookupTable
		{
			private readonly SecT239K1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT239K1CurveLookupTable(SecT239K1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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

				return outerInstance.createRawPoint(new SecT239FieldElement(x), new SecT239FieldElement(y), false);
			}
		}
	}

}