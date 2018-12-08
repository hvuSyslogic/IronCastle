namespace org.bouncycastle.openpgp.@operator
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;

	/// <summary>
	/// A digest calculator, which consumes a stream of data and computes a digest value over it.
	/// </summary>
	public interface PGPDigestCalculator
	{
		/// <summary>
		/// Return the <seealso cref="HashAlgorithmTags algorithm number"/> representing the digest implemented by
		/// this calculator.
		/// </summary>
		/// <returns> the hash algorithm number </returns>
		int getAlgorithm();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating a digest. Use
		/// org.bouncycastle.util.io.TeeOutputStream if you want to accumulate the data on the fly as
		/// well.
		/// </summary>
		/// <returns> an OutputStream that data to be digested can be written to. </returns>
		OutputStream getOutputStream();

		/// <summary>
		/// Return the digest calculated on what has been written to the calculator's output stream.
		/// </summary>
		/// <returns> a digest. </returns>
		byte[] getDigest();

		/// <summary>
		/// Reset the underlying digest calculator
		/// </summary>
		void reset();
	}

}