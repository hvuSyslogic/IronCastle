using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto
{

	
	public interface KeyParser
	{
		AsymmetricKeyParameter readKey(InputStream stream);
	}

}