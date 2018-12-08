using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public interface KeyParser
	{
		AsymmetricKeyParameter readKey(InputStream stream);
	}

}