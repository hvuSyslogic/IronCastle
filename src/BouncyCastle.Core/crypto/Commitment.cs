namespace org.bouncycastle.crypto
{
	/// <summary>
	/// General holding class for a commitment.
	/// </summary>
	public class Commitment
	{
		private readonly byte[] secret;
		private readonly byte[] commitment;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="secret">  an encoding of the secret required to reveal the commitment. </param>
		/// <param name="commitment">  an encoding of the sealed commitment. </param>
		public Commitment(byte[] secret, byte[] commitment)
		{
			this.secret = secret;
			this.commitment = commitment;
		}

		/// <summary>
		/// The secret required to reveal the commitment.
		/// </summary>
		/// <returns> an encoding of the secret associated with the commitment. </returns>
		public virtual byte[] getSecret()
		{
			return secret;
		}

		/// <summary>
		/// The sealed commitment.
		/// </summary>
		/// <returns> an encoding of the sealed commitment. </returns>
		public virtual byte[] getCommitment()
		{
			return commitment;
		}
	}

}