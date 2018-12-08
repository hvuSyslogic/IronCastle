namespace org.bouncycastle.jcajce.io
{

	public class DigestUpdatingOutputStream : OutputStream
	{
		private MessageDigest digest;

		public DigestUpdatingOutputStream(MessageDigest digest)
		{
			this.digest = digest;
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			digest.update(bytes, off, len);
		}

		public virtual void write(byte[] bytes)
		{
			digest.update(bytes);
		}

		public virtual void write(int b)
		{
			digest.update((byte)b);
		}
	}

}