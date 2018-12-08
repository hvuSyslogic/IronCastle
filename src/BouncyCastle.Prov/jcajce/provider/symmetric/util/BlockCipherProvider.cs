namespace org.bouncycastle.jcajce.provider.symmetric.util
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;

	public interface BlockCipherProvider
	{
		BlockCipher get();
	}

}