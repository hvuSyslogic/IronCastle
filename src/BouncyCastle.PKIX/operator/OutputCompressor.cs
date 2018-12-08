namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to produce
	/// an OutputStream that will output compressed data.
	/// </summary>
	public interface OutputCompressor
	{
		/// <summary>
		/// Return the algorithm identifier describing the compression
		/// algorithm and parameters this compressor uses.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Wrap the passed in output stream comOut, returning an output stream
		/// that compresses anything passed in before sending on to comOut.
		/// </summary>
		/// <param name="comOut"> output stream for compressed output. </param>
		/// <returns> a compressing OutputStream </returns>
		OutputStream getOutputStream(OutputStream comOut);
	}

}