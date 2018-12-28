using System;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class ByteQueueInputStream : InputStream
	{
		private ByteQueue buffer;

		public ByteQueueInputStream()
		{
			buffer = new ByteQueue();
		}

		public virtual void addBytes(byte[] bytes)
		{
			buffer.addData(bytes, 0, bytes.Length);
		}

		public virtual int peek(byte[] buf)
		{
			int bytesToRead = Math.Min(buffer.available(), buf.Length);
			buffer.read(buf, 0, bytesToRead, 0);
			return bytesToRead;
		}

		public override int read()
		{
			if (buffer.available() == 0)
			{
				return -1;
			}
			return buffer.removeData(1, 0)[0] & 0xFF;
		}

		public override int read(byte[] b)
		{
			return read(b, 0, b.Length);
		}

		public override int read(byte[] b, int off, int len)
		{
			int bytesToRead = Math.Min(buffer.available(), len);
			buffer.removeData(b, off, bytesToRead, 0);
			return bytesToRead;
		}

		public override long skip(long n)
		{
			int bytesToRemove = Math.Min((int)n, buffer.available());
			buffer.removeData(bytesToRemove);
			return bytesToRemove;
		}

		public override int available()
		{
			return buffer.available();
		}

		public override void close()
		{
		}
	}

}