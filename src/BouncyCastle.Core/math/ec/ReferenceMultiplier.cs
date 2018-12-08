using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	public class ReferenceMultiplier : AbstractECMultiplier
	{
		public override ECPoint multiplyPositive(ECPoint p, BigInteger k)
		{
			return ECAlgorithms.referenceMultiply(p, k);
		}
	}

}