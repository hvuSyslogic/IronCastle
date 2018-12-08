namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for an operator that is able to calculate a digest from
	/// a stream of output.
	/// </summary>
	public interface DigestCalculator
	{
		/// <summary>
		/// Return the algorithm identifier representing the digest implemented by
		/// this calculator.
		/// </summary>
		/// <returns> algorithm id and parameters. </returns>
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating
		/// a digest. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
		/// the data on the fly as well.
		/// </summary>
		/// <returns> an OutputStream </returns>
		OutputStream getOutputStream();

		/// <summary>
		/// Return the digest calculated on what has been written to the calculator's output stream.
		/// </summary>
		/// <returns> a digest. </returns>
		byte[] getDigest();
	}

}