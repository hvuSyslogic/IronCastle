using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.ec
{
	
	public interface ECEncryptor
	{
		void init(CipherParameters @params);

		ECPair encrypt(ECPoint point);
	}

}