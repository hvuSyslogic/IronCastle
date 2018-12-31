using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto
{
	
	public interface KeyEncoder
	{
		byte[] getEncoded(AsymmetricKeyParameter keyParameter);
	}

}