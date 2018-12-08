namespace org.bouncycastle.@operator
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General interface for a key initialized operator that is able to calculate a MAC from
	/// a stream of output.
	/// </summary>
	public interface MacCalculator
	{
		AlgorithmIdentifier getAlgorithmIdentifier();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating
		/// the MAC for later verification. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
		/// the data on the fly as well.
		/// </summary>
		/// <returns> an OutputStream </returns>
		OutputStream getOutputStream();

		/// <summary>
		/// Return the calculated MAC based on what has been written to the stream.
		/// </summary>
		/// <returns> calculated MAC. </returns>
		byte[] getMac();


		/// <summary>
		/// Return the key used for calculating the MAC.
		/// </summary>
		/// <returns> the MAC key. </returns>
		GenericKey getKey();
	}
}