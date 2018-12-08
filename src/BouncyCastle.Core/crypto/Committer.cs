namespace org.bouncycastle.crypto
{
	/// <summary>
	/// General interface fdr classes that produce and validate commitments.
	/// </summary>
	public interface Committer
	{
		/// <summary>
		/// Generate a commitment for the passed in message.
		/// </summary>
		/// <param name="message"> the message to be committed to, </param>
		/// <returns> a Commitment </returns>
		Commitment commit(byte[] message);

		/// <summary>
		/// Return true if the passed in commitment represents a commitment to the passed in maessage.
		/// </summary>
		/// <param name="commitment"> a commitment previously generated. </param>
		/// <param name="message"> the message that was expected to have been committed to. </param>
		/// <returns> true if commitment matches message, false otherwise. </returns>
		bool isRevealed(Commitment commitment, byte[] message);
	}

}