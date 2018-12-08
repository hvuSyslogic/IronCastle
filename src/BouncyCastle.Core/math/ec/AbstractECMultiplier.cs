using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	public abstract class AbstractECMultiplier : ECMultiplier
	{
		public virtual ECPoint multiply(ECPoint p, BigInteger k)
		{
			int sign = k.signum();
			if (sign == 0 || p.isInfinity())
			{
				return p.getCurve().getInfinity();
			}

			ECPoint positive = multiplyPositive(p, k.abs());
			ECPoint result = sign > 0 ? positive : positive.negate();

			/*
			 * Although the various multipliers ought not to produce invalid output under normal
			 * circumstances, a final check here is advised to guard against fault attacks.
			 */
			return checkResult(result);
		}

		public abstract ECPoint multiplyPositive(ECPoint p, BigInteger k);

		public virtual ECPoint checkResult(ECPoint p)
		{
			return ECAlgorithms.implCheckResult(p);
		}
	}

}