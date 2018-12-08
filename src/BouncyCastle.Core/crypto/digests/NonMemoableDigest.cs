using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.digests
{

	/// <summary>
	/// Wrapper removes exposure to the Memoable interface on an ExtendedDigest implementation.
	/// </summary>
	public class NonMemoableDigest : ExtendedDigest
	{
		private ExtendedDigest baseDigest;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="baseDigest"> underlying digest to use. </param>
		/// <exception cref="IllegalArgumentException"> if baseDigest is null </exception>
		public NonMemoableDigest(ExtendedDigest baseDigest)
		{
			if (baseDigest == null)
			{
				throw new IllegalArgumentException("baseDigest must not be null");
			}

			this.baseDigest = baseDigest;
		}

		public virtual string getAlgorithmName()
		{
			return baseDigest.getAlgorithmName();
		}

		public virtual int getDigestSize()
		{
			return baseDigest.getDigestSize();
		}

		public virtual void update(byte @in)
		{
			baseDigest.update(@in);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			baseDigest.update(@in, inOff, len);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			return baseDigest.doFinal(@out, outOff);
		}

		public virtual void reset()
		{
			baseDigest.reset();
		}

		public virtual int getByteLength()
		{
			return baseDigest.getByteLength();
		}
	}

}