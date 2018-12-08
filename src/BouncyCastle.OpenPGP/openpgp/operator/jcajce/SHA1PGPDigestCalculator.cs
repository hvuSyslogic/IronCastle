using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator.jcajce
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using OutputStreamFactory = org.bouncycastle.jcajce.io.OutputStreamFactory;

	public class SHA1PGPDigestCalculator : PGPDigestCalculator
	{
		private MessageDigest digest;

		public SHA1PGPDigestCalculator()
		{
			try
			{
				digest = MessageDigest.getInstance("SHA1");
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new IllegalStateException("cannot find SHA-1: " + e.Message);
			}
		}

		public virtual int getAlgorithm()
		{
			return HashAlgorithmTags_Fields.SHA1;
		}

		public virtual OutputStream getOutputStream()
		{
			return OutputStreamFactory.createStream(digest);
		}

		public virtual byte[] getDigest()
		{
			return digest.digest();
		}

		public virtual void reset()
		{
			digest.reset();
		}
	}

}