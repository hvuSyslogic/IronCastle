namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to create a signature from
	/// a stream of output.
	/// </summary>
	public interface ContentSigner
	{
		/// <summary>
		/// Return the algorithm identifier describing the signature
		/// algorithm and parameters this signer generates.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating
		/// a signature. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
		/// the data on the fly as well.
		/// </summary>
		/// <returns> an OutputStream </returns>
		OutputStream getOutputStream();

		/// <summary>
		/// Returns a signature based on the current data written to the stream, since the
		/// start or the last call to getSignature().
		/// </summary>
		/// <returns> bytes representing the signature. </returns>
		byte[] getSignature();
	}

}