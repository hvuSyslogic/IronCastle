using org.bouncycastle.notexisting;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class DigestInputStream : FilterInputStream
	{
		protected internal Digest digest;

		public DigestInputStream(InputStream stream, Digest digest) : base(stream)
		{
			this.digest = digest;
		}

		public virtual int read()
		{
			int b = @in.read();

			if (b >= 0)
			{
				digest.update((byte)b);
			}
			return b;
		}

		public virtual int read(byte[] b, int off, int len)
		{
			int n = @in.read(b, off, len);
			if (n > 0)
			{
				digest.update(b, off, n);
			}
			return n;
		}

		public virtual Digest getDigest()
		{
			return digest;
		}
	}

}