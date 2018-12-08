namespace org.bouncycastle.jcajce.io
{

	public class SignatureUpdatingOutputStream : OutputStream
	{
		private Signature sig;

		public SignatureUpdatingOutputStream(Signature sig)
		{
			this.sig = sig;
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			try
			{
				sig.update(bytes, off, len);
			}
			catch (SignatureException e)
			{
				throw new IOException(e.Message);
			}
		}

		public virtual void write(byte[] bytes)
		{
			try
			{
				sig.update(bytes);
			}
			catch (SignatureException e)
			{
				throw new IOException(e.Message);
			}
		}

		public virtual void write(int b)
		{
			try
			{
				sig.update((byte)b);
			}
			catch (SignatureException e)
			{
				throw new IOException(e.Message);
			}
		}
	}

}