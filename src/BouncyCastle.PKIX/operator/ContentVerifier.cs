namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to verify a signature based
	/// on data in a stream of output.
	/// </summary>
	public interface ContentVerifier
	{
		/// <summary>
		/// Return the algorithm identifier describing the signature
		/// algorithm and parameters this verifier supports.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating
		/// a signature for later verification. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
		/// the data on the fly as well.
		/// </summary>
		/// <returns> an OutputStream </returns>
		OutputStream getOutputStream();

		/// <summary>
		/// Return true if the expected value of the signature matches the data passed
		/// into the stream.
		/// </summary>
		/// <param name="expected"> expected value of the signature on the data. </param>
		/// <returns> true if the signature verifies, false otherwise </returns>
		bool verify(byte[] expected);
	}
}