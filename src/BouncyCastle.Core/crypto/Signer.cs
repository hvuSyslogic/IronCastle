namespace org.bouncycastle.crypto
{
	/// <summary>
	/// Generic signer interface for hash based and message recovery signers.
	/// </summary>
	public interface Signer
	{
		/// <summary>
		/// Initialise the signer for signing or verification.
		/// </summary>
		/// <param name="forSigning"> true if for signing, false otherwise </param>
		/// <param name="param"> necessary parameters. </param>
		void init(bool forSigning, CipherParameters param);

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		void update(byte b);

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		void update(byte[] @in, int off, int len);

		/// <summary>
		/// generate a signature for the message we've been loaded with using
		/// the key we were initialised with.
		/// </summary>
		byte[] generateSignature();

		/// <summary>
		/// return true if the internal state represents the signature described
		/// in the passed in array.
		/// </summary>
		bool verifySignature(byte[] signature);

		/// <summary>
		/// reset the internal state
		/// </summary>
		void reset();
	}

}