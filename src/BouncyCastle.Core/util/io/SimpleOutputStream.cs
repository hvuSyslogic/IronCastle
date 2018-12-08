using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{

	public abstract class SimpleOutputStream : OutputStream
	{
		public virtual void close()
		{
		}

		public virtual void flush()
		{
		}

		public virtual void write(int b)
		{
			byte[] buf = new byte[]{(byte)b};
			write(buf, 0, 1);
		}
	}

}