namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to produce
	/// an InputStream that will produce uncompressed data.
	/// </summary>
	public interface InputExpander
	{
		/// <summary>
		/// Return the algorithm identifier describing the compression
		/// algorithm and parameters this expander supports.
		/// </summary>
		/// <returns> algorithm oid and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Wrap the passed in input stream comIn, returning an input stream
		/// that expands anything read in from comIn.
		/// </summary>
		/// <param name="comIn"> the compressed input data stream.. </param>
		/// <returns> an expanding InputStream. </returns>
		InputStream getInputStream(InputStream comIn);
	}

}