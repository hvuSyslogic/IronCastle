namespace org.bouncycastle.crypto.tls.test
{

	/// <summary>
	/// Tracks and enforces close() calls, without closing the underlying OutputStream
	/// </summary>
	public class NetworkOutputStream : FilterOutputStream
	{
		internal bool closed = false;

		public NetworkOutputStream(OutputStream output) : base(output)
		{
		}

		public virtual bool isClosed()
		{
			lock (this)
			{
				return closed;
			}
		}

		public virtual void close()
		{
			lock (this)
			{
				closed = true;
			}
		}

		public virtual void write(int b)
		{
			checkNotClosed();
			@out.write(b);
		}

		public virtual void write(byte[] b)
		{
			checkNotClosed();
			@out.write(b);
		}

		public virtual void write(byte[] b, int off, int len)
		{
			checkNotClosed();
			@out.write(b, off, len);
		}

		public virtual void checkNotClosed()
		{
			lock (this)
			{
				if (closed)
				{
					throw new IOException("NetworkOutputStream closed");
				}
			}
		}
	}

}