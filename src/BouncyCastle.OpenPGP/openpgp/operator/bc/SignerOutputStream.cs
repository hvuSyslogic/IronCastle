namespace org.bouncycastle.openpgp.@operator.bc
{

	using Signer = org.bouncycastle.crypto.Signer;

	public class SignerOutputStream : OutputStream
	{
		private Signer sig;

		public SignerOutputStream(Signer sig)
		{
			this.sig = sig;
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			sig.update(bytes, off, len);
		}

		public virtual void write(byte[] bytes)
		{
			sig.update(bytes, 0, bytes.Length);
		}

		public virtual void write(int b)
		{
			sig.update((byte)b);
		}
	}

}