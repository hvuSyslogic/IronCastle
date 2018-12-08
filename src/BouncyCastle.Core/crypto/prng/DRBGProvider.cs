namespace org.bouncycastle.crypto.prng
{
	using SP80090DRBG = org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

	public interface DRBGProvider
	{
		SP80090DRBG get(EntropySource entropySource);
	}

}