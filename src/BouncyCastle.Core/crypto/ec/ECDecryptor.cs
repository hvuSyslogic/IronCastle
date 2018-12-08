namespace org.bouncycastle.crypto.ec
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public interface ECDecryptor
	{
		void init(CipherParameters @params);

		ECPoint decrypt(ECPair cipherText);
	}

}