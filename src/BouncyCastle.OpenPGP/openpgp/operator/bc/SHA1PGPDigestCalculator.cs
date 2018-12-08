using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator.bc
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;

	public class SHA1PGPDigestCalculator : PGPDigestCalculator
	{
		private Digest digest = new SHA1Digest();

		public virtual int getAlgorithm()
		{
			return HashAlgorithmTags_Fields.SHA1;
		}

		public virtual OutputStream getOutputStream()
		{
			return new DigestOutputStream(this, digest);
		}

		public virtual byte[] getDigest()
		{
			byte[] d = new byte[digest.getDigestSize()];

			digest.doFinal(d, 0);

			return d;
		}

		public virtual void reset()
		{
			digest.reset();
		}

		public class DigestOutputStream : OutputStream
		{
			private readonly SHA1PGPDigestCalculator outerInstance;

			internal Digest dig;

			public DigestOutputStream(SHA1PGPDigestCalculator outerInstance, Digest dig)
			{
				this.outerInstance = outerInstance;
				this.dig = dig;
			}

			public virtual void write(byte[] bytes, int off, int len)
			{
				dig.update(bytes, off, len);
			}

			public virtual void write(byte[] bytes)
			{
				dig.update(bytes, 0, bytes.Length);
			}

			public virtual void write(int b)
			{
				dig.update((byte)b);
			}
		}
	}

}