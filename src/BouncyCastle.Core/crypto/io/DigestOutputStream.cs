using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class DigestOutputStream : OutputStream
	{
		protected internal Digest digest;

		public DigestOutputStream(Digest org)
		{
			this.digest = org;
		}

		public override void write(int b)
		{
			digest.update((byte)b);
		}

		public override void write(byte[] b, int off, int len)
		{
			digest.update(b, off, len);
		}

		public virtual byte[] getDigest()
		{
			byte[] res = new byte[digest.getDigestSize()];

			digest.doFinal(res, 0);

			return res;
		}
	}

}