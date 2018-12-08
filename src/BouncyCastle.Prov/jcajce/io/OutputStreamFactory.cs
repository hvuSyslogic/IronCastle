namespace org.bouncycastle.jcajce.io
{

	/// <summary>
	/// Utility class for creating OutputStreams from different JCA/JCE operators.
	/// </summary>
	public class OutputStreamFactory
	{
		/// <summary>
		/// Create an OutputStream that wraps a signature.
		/// </summary>
		/// <param name="signature"> the signature to be updated as the stream is written to. </param>
		/// <returns> an OutputStream. </returns>
		public static OutputStream createStream(Signature signature)
		{
			return new SignatureUpdatingOutputStream(signature);
		}

		/// <summary>
		/// Create an OutputStream that wraps a digest.
		/// </summary>
		/// <param name="digest"> the digest to be updated as the stream is written to. </param>
		/// <returns> an OutputStream. </returns>
		public static OutputStream createStream(MessageDigest digest)
		{
			return new DigestUpdatingOutputStream(digest);
		}

		/// <summary>
		/// Create an OutputStream that wraps a mac.
		/// </summary>
		/// <param name="mac"> the signature to be updated as the stream is written to. </param>
		/// <returns> an OutputStream. </returns>
		public static OutputStream createStream(Mac mac)
		{
			return new MacUpdatingOutputStream(mac);
		}
	}

}