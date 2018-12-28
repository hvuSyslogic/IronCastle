using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec.custom.djb
{

	using Nat256 = org.bouncycastle.math.raw.Nat256;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class Curve25519 : ECCurve.AbstractFp
	{
		public static readonly BigInteger q = Nat256.toBigInteger(Curve25519Field.P);

		private const int Curve25519_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;

		protected internal Curve25519Point infinity;

		public Curve25519() : base(q)
		{

			this.infinity = new Curve25519Point(this, null, null);

			this.a = fromBigInteger(new BigInteger(1, Hex.decode("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144")));
			this.b = fromBigInteger(new BigInteger(1, Hex.decode("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864")));
			this.order = new BigInteger(1, Hex.decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
			this.cofactor = BigInteger.valueOf(8);

			this.coord = Curve25519_DEFAULT_COORDS;
		}

		public override ECCurve cloneCurve()
		{
			return new Curve25519();
		}

		public override bool supportsCoordinateSystem(int coord)
		{
			switch (coord)
			{
			case COORD_JACOBIAN_MODIFIED:
				return true;
			default:
				return false;
			}
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		public override int getFieldSize()
		{
			return q.bitLength();
		}

		public override ECFieldElement fromBigInteger(BigInteger x)
		{
			return new Curve25519FieldElement(x);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
		{
			return new Curve25519Point(this, x, y, withCompression);
		}

		public override ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
		{
			return new Curve25519Point(this, x, y, zs, withCompression);
		}

		public override ECPoint getInfinity()
		{
			return infinity;
		}

		public override ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, int len)
		{
			const int FE_INTS = 8;

			int[] table = new int[len * FE_INTS * 2];
			{
				int pos = 0;
				for (int i = 0; i < len; ++i)
				{
					ECPoint p = points[off + i];
					Nat256.copy(((Curve25519FieldElement)p.getRawXCoord()).x, 0, table, pos);
					pos += FE_INTS;
					Nat256.copy(((Curve25519FieldElement)p.getRawYCoord()).x, 0, table, pos);
					pos += FE_INTS;
				}
			}

			return new ECLookupTableAnonymousInnerClass(this, len, FE_INTS, table);
		}

		public class ECLookupTableAnonymousInnerClass : ECLookupTable
		{
			private readonly Curve25519 outerInstance;

			private int len;
			private int FE_INTS;
			private int[] table;

			public ECLookupTableAnonymousInnerClass(Curve25519 outerInstance, int len, int FE_INTS, int[] table)
			{
				this.outerInstance = outerInstance;
				this.len = len;
				this.FE_INTS = FE_INTS;
				this.table = table;
			}

			public int getSize()
			{
				return len;
			}

			public ECPoint lookup(int index)
			{
				int[] x = Nat256.create(), y = Nat256.create();
				int pos = 0;

				for (int i = 0; i < len; ++i)
				{
					int MASK = ((i ^ index) - 1) >> 31;

					for (int j = 0; j < FE_INTS; ++j)
					{
						x[j] ^= table[pos + j] & MASK;
						y[j] ^= table[pos + FE_INTS + j] & MASK;
					}

					pos += (FE_INTS * 2);
				}

				return outerInstance.createRawPoint(new Curve25519FieldElement(x), new Curve25519FieldElement(y), false);
			}
		}
	}

}