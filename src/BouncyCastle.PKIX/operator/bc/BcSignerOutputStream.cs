namespace org.bouncycastle.@operator.bc
{

	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using Signer = org.bouncycastle.crypto.Signer;

	public class BcSignerOutputStream : OutputStream
	{
		private Signer sig;

		public BcSignerOutputStream(Signer sig)
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

		public virtual byte[] getSignature()
		{
			return sig.generateSignature();
		}

		public virtual bool verify(byte[] expected)
		{
			return sig.verifySignature(expected);
		}
	}
}