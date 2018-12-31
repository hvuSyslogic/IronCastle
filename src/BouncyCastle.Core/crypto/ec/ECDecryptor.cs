using org.bouncycastle.math.ec;

namespace org.bouncycastle.crypto.ec
{
	
	public interface ECDecryptor
	{
		void init(CipherParameters @params);

		ECPoint decrypt(ECPair cipherText);
	}

}