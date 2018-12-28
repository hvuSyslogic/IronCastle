using org.bouncycastle.notexisting;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class MacInputStream : FilterInputStream
	{
		protected internal Mac mac;

		public MacInputStream(InputStream stream, Mac mac) : base(stream)
		{
			this.mac = mac;
		}

		public override int read()
		{
			int b = @in.read();

			if (b >= 0)
			{
				mac.update((byte)b);
			}
			return b;
		}

		public override int read(byte[] b, int off, int len)
		{
			int n = @in.read(b, off, len);
			if (n >= 0)
			{
				mac.update(b, off, n);
			}
			return n;
		}

		public virtual Mac getMac()
		{
			return mac;
		}
	}

}