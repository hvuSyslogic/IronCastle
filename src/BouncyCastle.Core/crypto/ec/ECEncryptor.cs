namespace org.bouncycastle.crypto.ec
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public interface ECEncryptor
	{
		void init(CipherParameters @params);

		ECPair encrypt(ECPoint point);
	}

}