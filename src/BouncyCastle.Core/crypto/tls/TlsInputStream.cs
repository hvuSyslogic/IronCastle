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

		public override int available()
		{
			return this.handler.applicationDataAvailable();
		}

		public override int read(byte[] buf, int offset, int len)
		{
			return this.handler.readApplicationData(buf, offset, len);
		}

		public override int read()
		{
			if (this.read(buf) < 0)
			{
				return -1;
			}
			return buf[0] & 0xff;
		}

		public override void close()
		{
			handler.close();
		}
	}

}