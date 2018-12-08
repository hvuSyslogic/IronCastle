namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to produce
	/// an InputStream that will decrypt a stream of encrypted data.
	/// </summary>
	public interface InputDecryptor
	{
		/// <summary>
		/// Return the algorithm identifier describing the encryption
		/// algorithm and parameters this decryptor can process.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Wrap the passed in input stream encIn, returning an input stream
		/// that decrypts what it reads from encIn before returning it.
		/// </summary>
		/// <param name="encIn"> InputStream containing encrypted input. </param>
		/// <returns> an decrypting InputStream </returns>
		InputStream getInputStream(InputStream encIn);
	}

}