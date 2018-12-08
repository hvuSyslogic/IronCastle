using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class ByteQueueOutputStream : OutputStream
	{
		private ByteQueue buffer;

		public ByteQueueOutputStream()
		{
			buffer = new ByteQueue();
		}

		public virtual ByteQueue getBuffer()
		{
			return buffer;
		}

		public virtual void write(int b)
		{
			buffer.addData(new byte[]{(byte)b}, 0, 1);
		}

		public virtual void write(byte[] b, int off, int len)
		{
			buffer.addData(b, off, len);
		}
	}

}