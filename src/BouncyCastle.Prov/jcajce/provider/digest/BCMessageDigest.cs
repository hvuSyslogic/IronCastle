namespace org.bouncycastle.jcajce.provider.digest
{

	using Digest = org.bouncycastle.crypto.Digest;

	public class BCMessageDigest : MessageDigest
	{
		protected internal Digest digest;

		public BCMessageDigest(Digest digest) : base(digest.getAlgorithmName())
		{

			this.digest = digest;
		}

		public virtual void engineReset()
		{
			digest.reset();
		}

		public virtual void engineUpdate(byte input)
		{
			digest.update(input);
		}

		public virtual void engineUpdate(byte[] input, int offset, int len)
		{
			digest.update(input, offset, len);
		}

		public virtual byte[] engineDigest()
		{
			byte[] digestBytes = new byte[digest.getDigestSize()];

			digest.doFinal(digestBytes, 0);

			return digestBytes;
		}
	}

}