namespace org.bouncycastle.crypto.prng
{
	public interface EntropySourceProvider
	{

		EntropySource get(int bitsRequired);
	}

}