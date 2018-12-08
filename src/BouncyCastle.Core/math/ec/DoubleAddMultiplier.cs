using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	public class DoubleAddMultiplier : AbstractECMultiplier
	{
		/// <summary>
		/// Joye's double-add algorithm.
		/// </summary>
		public override ECPoint multiplyPositive(ECPoint p, BigInteger k)
		{
			ECPoint[] R = new ECPoint[]{p.getCurve().getInfinity(), p};

			int n = k.bitLength();
			for (int i = 0; i < n; ++i)
			{
				int b = k.testBit(i) ? 1 : 0;
				int bp = 1 - b;
				R[bp] = R[bp].twicePlus(R[b]);
			}

			return R[0];
		}
	}

}