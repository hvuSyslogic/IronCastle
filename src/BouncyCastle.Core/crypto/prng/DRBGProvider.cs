using org.bouncycastle.crypto.prng.drbg;

namespace org.bouncycastle.crypto.prng
{
	
	public interface DRBGProvider
	{
		SP80090DRBG get(EntropySource entropySource);
	}

}