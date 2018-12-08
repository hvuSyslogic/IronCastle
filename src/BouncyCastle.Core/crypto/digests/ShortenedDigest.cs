using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.digests
{

	/// <summary>
	/// Wrapper class that reduces the output length of a particular digest to
	/// only the first n bytes of the digest function.
	/// </summary>
	public class ShortenedDigest : ExtendedDigest
	{
		private ExtendedDigest baseDigest;
		private int length;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="baseDigest"> underlying digest to use. </param>
		/// <param name="length"> length in bytes of the output of doFinal. </param>
		/// <exception cref="IllegalArgumentException"> if baseDigest is null, or length is greater than baseDigest.getDigestSize(). </exception>
		public ShortenedDigest(ExtendedDigest baseDigest, int length)
		{
			if (baseDigest == null)
			{
				throw new IllegalArgumentException("baseDigest must not be null");
			}

			if (length > baseDigest.getDigestSize())
			{
				throw new IllegalArgumentException("baseDigest output not large enough to support length");
			}

			this.baseDigest = baseDigest;
			this.length = length;
		}

		public virtual string getAlgorithmName()
		{
			return baseDigest.getAlgorithmName() + "(" + length * 8 + ")";
		}

		public virtual int getDigestSize()
		{
			return length;
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
			byte[] tmp = new byte[baseDigest.getDigestSize()];

			baseDigest.doFinal(tmp, 0);

			JavaSystem.arraycopy(tmp, 0, @out, outOff, length);

			return length;
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