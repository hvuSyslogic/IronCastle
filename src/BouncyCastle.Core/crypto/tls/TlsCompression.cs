using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public interface TlsCompression
	{
		OutputStream compress(OutputStream output);

		OutputStream decompress(OutputStream output);
	}

}