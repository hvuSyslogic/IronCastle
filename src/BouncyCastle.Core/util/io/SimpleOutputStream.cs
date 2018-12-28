using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{

	public abstract class SimpleOutputStream : OutputStream
	{
		public override void close()
		{
		}

		public override void flush()
		{
		}

		public override void write(int b)
		{
			byte[] buf = new byte[]{(byte)b};
			write(buf, 0, 1);
		}
	}

}