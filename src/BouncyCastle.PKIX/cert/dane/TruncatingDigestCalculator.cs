namespace org.bouncycastle.cert.dane
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// A calculator which produces a truncated digest from a regular one, with the truncation
	/// achieved by dropping off the right most octets.
	/// </summary>
	public class TruncatingDigestCalculator : DigestCalculator
	{
		private readonly DigestCalculator baseCalculator;
		private readonly int length;

		/// <summary>
		/// Default constructor - truncate to 28.
		/// </summary>
		/// <param name="baseCalculator"> actual calculator for working out the digest. </param>
		public TruncatingDigestCalculator(DigestCalculator baseCalculator) : this(baseCalculator, 28)
		{
		}

		/// <summary>
		/// Constructor specifying a length.
		/// </summary>
		/// <param name="baseCalculator"> actual calculator for working out the digest. </param>
		/// <param name="length"> length in bytes of the final result. </param>
		public TruncatingDigestCalculator(DigestCalculator baseCalculator, int length)
		{
			this.baseCalculator = baseCalculator;
			this.length = length;
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return baseCalculator.getAlgorithmIdentifier();
		}

		public virtual OutputStream getOutputStream()
		{
			return baseCalculator.getOutputStream();
		}

		public virtual byte[] getDigest()
		{
			byte[] rv = new byte[length];

			byte[] dig = baseCalculator.getDigest();

			JavaSystem.arraycopy(dig, 0, rv, 0, rv.Length);

			return rv;
		}
	}

}