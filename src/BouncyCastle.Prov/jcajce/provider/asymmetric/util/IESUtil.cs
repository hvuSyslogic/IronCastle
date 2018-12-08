namespace org.bouncycastle.jcajce.provider.asymmetric.util
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using IESParameterSpec = org.bouncycastle.jce.spec.IESParameterSpec;

	public class IESUtil
	{
		public static IESParameterSpec guessParameterSpec(BufferedBlockCipher iesBlockCipher, byte[] nonce)
		{
			if (iesBlockCipher == null)
			{
				return new IESParameterSpec(null, null, 128);
			}
			else
			{
				BlockCipher underlyingCipher = iesBlockCipher.getUnderlyingCipher();

				if (underlyingCipher.getAlgorithmName().Equals("DES") || underlyingCipher.getAlgorithmName().Equals("RC2") || underlyingCipher.getAlgorithmName().Equals("RC5-32") || underlyingCipher.getAlgorithmName().Equals("RC5-64"))
				{
					return new IESParameterSpec(null, null, 64, 64, nonce);
				}
				else if (underlyingCipher.getAlgorithmName().Equals("SKIPJACK"))
				{
					return new IESParameterSpec(null, null, 80, 80, nonce);
				}
				else if (underlyingCipher.getAlgorithmName().Equals("GOST28147"))
				{
					return new IESParameterSpec(null, null, 256, 256, nonce);
				}

				return new IESParameterSpec(null, null, 128, 128, nonce);
			}
		}
	}

}