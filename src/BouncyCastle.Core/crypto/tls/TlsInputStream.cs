using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// An InputStream for an TLS 1.0 connection.
	/// </summary>
	public class TlsInputStream : InputStream
	{
		private byte[] buf = new byte[1];
		private TlsProtocol handler = null;

		public TlsInputStream(TlsProtocol handler)
		{
			this.handler = handler;
		}

		public virtual int available()
		{
			return this.handler.applicationDataAvailable();
		}

		public virtual int read(byte[] buf, int offset, int len)
		{
			return this.handler.readApplicationData(buf, offset, len);
		}

		public virtual int read()
		{
			if (this.read(buf) < 0)
			{
				return -1;
			}
			return buf[0] & 0xff;
		}

		public virtual void close()
		{
			handler.close();
		}
	}

}