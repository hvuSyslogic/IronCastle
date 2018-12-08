namespace org.bouncycastle.pqc.crypto
{
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;

	/// <summary>
	/// Base interface for a PQC signing algorithm.
	/// </summary>
	public interface MessageSigner
	{
		/// <summary>
		/// initialise the signer for signature generation or signature
		/// verification.
		/// </summary>
		/// <param name="forSigning"> true if we are generating a signature, false
		///                   otherwise. </param>
		/// <param name="param">      key parameters for signature generation. </param>
		void init(bool forSigning, CipherParameters param);

		/// <summary>
		/// sign the passed in message (usually the output of a hash function).
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <returns> the signature of the message </returns>
		byte[] generateSignature(byte[] message);

		/// <summary>
		/// verify the message message against the signature value.
		/// </summary>
		/// <param name="message"> the message that was supposed to have been signed. </param>
		/// <param name="signature"> the signature of the message </param>
		bool verifySignature(byte[] message, byte[] signature);
	}

}