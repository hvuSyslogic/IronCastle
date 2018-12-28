using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class SignerOutputStream : OutputStream
	{
		protected internal Signer _signer;

		public SignerOutputStream(Signer signer)
		{
			this._signer = signer;
		}

		public override void write(int b)
		{
		    _signer.update((byte)b);
		}

		public override void write(byte[] b, int off, int len)
		{
		    _signer.update(b, off, len);
		}

		public virtual Signer getSigner()
		{
			return _signer;
		}
	}

}