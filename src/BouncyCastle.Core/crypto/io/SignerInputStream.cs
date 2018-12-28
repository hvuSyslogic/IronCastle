using org.bouncycastle.notexisting;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class SignerInputStream : FilterInputStream
	{
		protected internal Signer signer;

		public SignerInputStream(InputStream stream, Signer signer) : base(stream)
		{
			this.signer = signer;
		}

		public override int read()
		{
			int b = @in.read();

			if (b >= 0)
			{
				signer.update((byte)b);
			}
			return b;
		}

		public override int read(byte[] b, int off, int len)
		{
			int n = @in.read(b, off, len);
			if (n > 0)
			{
				signer.update(b, off, n);
			}
			return n;
		}

		public virtual Signer getSigner()
		{
			return signer;
		}
	}

}