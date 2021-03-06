﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util.encoders;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.sec
{

		
	public class SecT283R1Curve : ECCurve.AbstractF2m
	{
		private const int SecT283R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

		protected internal SecT283R1Point infinity;

		public SecT283R1Curve() : base(283, 5, 7, 12)
		{

			this.infinity = new SecT283R1Point(this, null, null);

			this.a = fromBigInteger(BigInteger.valueOf(1));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5")));
			this.order = new BigInteger(1, Hex.decode("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307"));
			this.cofactor = BigInteger.valueOf(2);

			this.coord = SecT283R1_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new SecT283R1Curve();
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
			return 283;
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new SecT283FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new SecT283R1Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new SecT283R1Point(this, x, y, zs, withCompression);
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
			return 283;
		}

		public virtual bool isTrinomial()
		{
			return false;
		}

		public virtual int getK1()
		{
			return 5;
		}

		public virtual int getK2()
		{
			return 7;
		}

		public virtual int getK3()
		{
			return 12;
		}


		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_LONGS = 5;


			ulong[] table = new ulong[len * FE_LONGS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat320.copy64(((SecT283FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_LONGS;
					Nat320.copy64(((SecT283FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_LONGS;
				}
			}

			return new SecT283R1CurveLookupTable(this, len, FE_LONGS, table);
		}

		public class SecT283R1CurveLookupTable : ECLookupTable
		{
			private readonly SecT283R1Curve outerInstance;

			private int len;
			private int FE_LONGS;
			private ulong[] table;

			public SecT283R1CurveLookupTable(SecT283R1Curve outerInstance, int len, int FE_LONGS, ulong[] table)
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
				ulong[] x = Nat320.create64(), y = Nat320.create64();
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

				return outerInstance.createRawPoint(new SecT283FieldElement(x), new SecT283FieldElement(y), false);
			}
		}
	}

}