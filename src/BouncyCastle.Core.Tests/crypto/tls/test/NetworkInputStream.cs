namespace org.bouncycastle.crypto.tls.test
{

	/// <summary>
	/// Tracks and enforces close() calls, without closing the underlying InputStream
	/// </summary>
	public class NetworkInputStream : FilterInputStream
	{
		internal bool closed = false;

		public NetworkInputStream(InputStream input) : base(input)
		{
		}

		public virtual bool isClosed()
		{
			lock (this)
			{
				return closed;
			}
		}

		public virtual int available()
		{
			checkNotClosed();
			return @in.available();
		}

		public virtual void close()
		{
			lock (this)
			{
				closed = true;
			}
		}

		public virtual int read()
		{
			checkNotClosed();
			return @in.read();
		}

		public virtual int read(byte[] b)
		{
			checkNotClosed();
			return @in.read(b);
		}

		public virtual int read(byte[] b, int off, int len)
		{
			checkNotClosed();
			return @in.read(b, off, len);
		}

		public virtual void checkNotClosed()
		{
			lock (this)
			{
				if (closed)
				{
					throw new IOException("NetworkInputStream closed");
				}
			}
		}
	}
}