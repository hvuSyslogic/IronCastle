using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec.endo;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec
{

	
	public class GLVMultiplier : AbstractECMultiplier
	{
		protected internal readonly ECCurve curve;
		protected internal readonly GLVEndomorphism glvEndomorphism;

		public GLVMultiplier(ECCurve curve, GLVEndomorphism glvEndomorphism)
		{
			if (curve == null || curve.getOrder() == null)
			{
				throw new IllegalArgumentException("Need curve with known group order");
			}

			this.curve = curve;
			this.glvEndomorphism = glvEndomorphism;
		}

		public override ECPoint multiplyPositive(ECPoint p, BigInteger k)
		{
			if (!curve.Equals(p.getCurve()))
			{
				throw new IllegalStateException();
			}

			BigInteger n = p.getCurve().getOrder();
			BigInteger[] ab = glvEndomorphism.decomposeScalar(k.mod(n));
			BigInteger a = ab[0], b = ab[1];

			ECPointMap pointMap = glvEndomorphism.getPointMap();
			if (glvEndomorphism.hasEfficientPointMap())
			{
				return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap, b);
			}

			return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap.map(p), b);
		}
	}

}