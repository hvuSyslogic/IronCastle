using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class SignerOutputStream : OutputStream
	{
		protected internal Signer signer;

		public SignerOutputStream(Signer org)
		{
			this.signer = Signer;
		}

		public virtual void write(int b)
		{
			signer.update((byte)b);
		}

		public virtual void write(byte[] b, int off, int len)
		{
			signer.update(b, off, len);
		}

		public virtual Signer getSigner()
		{
			return signer;
		}
	}

}