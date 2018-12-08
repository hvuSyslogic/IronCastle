namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to produce
	/// an OutputStream that will output encrypted data.
	/// </summary>
	public interface OutputEncryptor
	{
		/// <summary>
		/// Return the algorithm identifier describing the encryption
		/// algorithm and parameters this encryptor uses.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Wrap the passed in output stream encOut, returning an output stream
		/// that encrypts anything passed in before sending on to encOut.
		/// </summary>
		/// <param name="encOut"> output stream for encrypted output. </param>
		/// <returns> an encrypting OutputStream </returns>
		OutputStream getOutputStream(OutputStream encOut);

		/// <summary>
		/// Return the key used for encrypting the output.
		/// </summary>
		/// <returns> the encryption key. </returns>
		GenericKey getKey();
	}

}