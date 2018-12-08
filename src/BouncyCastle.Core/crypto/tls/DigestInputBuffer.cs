using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	public class DigestInputBuffer : ByteArrayOutputStream
	{
		public virtual void updateDigest(Digest d)
		{
			d.update(this.buf, 0, count());
		}
	}

}