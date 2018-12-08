using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class SignerInputBuffer : ByteArrayOutputStream
	{
		public virtual void updateSigner(Signer s)
		{
			s.update(this.buf, 0, count());
		}
	}
}