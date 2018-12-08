using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// An OutputStream for an TLS connection.
	/// </summary>
	public class TlsOutputStream : OutputStream
	{
		private byte[] buf = new byte[1];
		private TlsProtocol handler;

		public TlsOutputStream(TlsProtocol handler)
		{
			this.handler = handler;
		}

		public virtual void write(byte[] buf, int offset, int len)
		{
			this.handler.writeData(buf, offset, len);
		}

		public virtual void write(int arg0)
		{
			buf[0] = (byte)arg0;
			this.write(buf, 0, 1);
		}

		public virtual void close()
		{
			handler.close();
		}

		public virtual void flush()
		{
			handler.flush();
		}
	}

}