using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec.endo
{

	public interface GLVEndomorphism : ECEndomorphism
	{
		BigInteger[] decomposeScalar(BigInteger k);
	}

}