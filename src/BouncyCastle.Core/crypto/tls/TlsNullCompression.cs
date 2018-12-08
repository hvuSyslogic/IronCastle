using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class TlsNullCompression : TlsCompression
	{
		public virtual OutputStream compress(OutputStream output)
		{
			return output;
		}

		public virtual OutputStream decompress(OutputStream output)
		{
			return output;
		}
	}

}