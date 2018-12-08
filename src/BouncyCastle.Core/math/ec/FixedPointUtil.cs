using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.math.ec
{

	public class FixedPointUtil
	{
		public const string PRECOMP_NAME = "bc_fixed_point";

		public static int getCombSize(ECCurve c)
		{
			BigInteger order = c.getOrder();
			return order == null ? c.getFieldSize() + 1 : order.bitLength();
		}

		public static FixedPointPreCompInfo getFixedPointPreCompInfo(PreCompInfo preCompInfo)
		{
			return (preCompInfo is FixedPointPreCompInfo) ? (FixedPointPreCompInfo)preCompInfo : null;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static FixedPointPreCompInfo precompute(final ECPoint p)
		public static FixedPointPreCompInfo precompute(ECPoint p)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final ECCurve c = p.getCurve();
			ECCurve c = p.getCurve();

			return (FixedPointPreCompInfo)c.precompute(p, PRECOMP_NAME, new PreCompCallbackAnonymousInnerClass(p, c));
		}

		public class PreCompCallbackAnonymousInnerClass : PreCompCallback
		{
			private ECPoint p;
			private ECCurve c;

			public PreCompCallbackAnonymousInnerClass(ECPoint p, ECCurve c)
			{
				this.p = p;
				this.c = c;
			}

			public PreCompInfo precompute(PreCompInfo existing)
			{
				FixedPointPreCompInfo existingFP = (existing is FixedPointPreCompInfo) ? (FixedPointPreCompInfo)existing : null;

				int bits = getCombSize(c);
				int minWidth = bits > 250 ? 6 : 5;
				int n = 1 << minWidth;

				if (checkExisting(existingFP, n))
				{
					return existingFP;
				}

				int d = (bits + minWidth - 1) / minWidth;

				ECPoint[] pow2Table = new ECPoint[minWidth + 1];
				pow2Table[0] = p;
				for (int i = 1; i < minWidth; ++i)
				{
					pow2Table[i] = pow2Table[i - 1].timesPow2(d);
				}

				// This will be the 'offset' value 
				pow2Table[minWidth] = pow2Table[0].subtract(pow2Table[1]);

				c.normalizeAll(pow2Table);

				ECPoint[] lookupTable = new ECPoint[n];
				lookupTable[0] = pow2Table[0];

				for (int bit = minWidth - 1; bit >= 0; --bit)
				{
					ECPoint pow2 = pow2Table[bit];

					int step = 1 << bit;
					for (int i = step; i < n; i += (step << 1))
					{
						lookupTable[i] = lookupTable[i - step].add(pow2);
					}
				}

				c.normalizeAll(lookupTable);

				FixedPointPreCompInfo result = new FixedPointPreCompInfo();
				result.setLookupTable(c.createCacheSafeLookupTable(lookupTable, 0, lookupTable.Length));
				result.setOffset(pow2Table[minWidth]);
				result.setWidth(minWidth);
				return result;
			}

			private bool checkExisting(FixedPointPreCompInfo existingFP, int n)
			{
				return existingFP != null && checkTable(existingFP.getLookupTable(), n);
			}

			private bool checkTable(ECLookupTable table, int n)
			{
				return table != null && table.getSize() >= n;
			}
		}
	}

}