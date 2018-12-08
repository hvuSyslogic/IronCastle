using org.bouncycastle.Port;

namespace org.bouncycastle.crypto
{
	/// <summary>
	/// Signer with message recovery.
	/// </summary>
	public interface SignerWithRecovery : Signer
	{
		/// <summary>
		/// Returns true if the signer has recovered the full message as
		/// part of signature verification.
		/// </summary>
		/// <returns> true if full message recovered. </returns>
		bool hasFullMessage();

		/// <summary>
		/// Returns a reference to what message was recovered (if any).
		/// </summary>
		/// <returns> full/partial message, null if nothing. </returns>
		byte[] getRecoveredMessage();

		/// <summary>
		/// Perform an update with the recovered message before adding any other data. This must
		/// be the first update method called, and calling it will result in the signer assuming
		/// that further calls to update will include message content past what is recoverable.
		/// </summary>
		/// <param name="signature"> the signature that we are in the process of verifying. </param>
		/// <exception cref="IllegalStateException"> </exception>
		void updateWithRecoveredMessage(byte[] signature);
	}

}