namespace org.bouncycastle.crypto.ec
{

	public interface ECPairTransform
	{
		void init(CipherParameters @params);

		ECPair transform(ECPair cipherText);
	}

}