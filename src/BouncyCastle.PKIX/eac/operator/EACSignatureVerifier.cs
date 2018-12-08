namespace org.bouncycastle.eac.@operator
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public interface EACSignatureVerifier
	{
		/// <summary>
		/// Return the usage OID specifying the signature type.
		/// </summary>
		/// <returns> algorithm oid. </returns>
		ASN1ObjectIdentifier getUsageIdentifier();

		/// <summary>
		/// Returns a stream that will accept data for the purpose of calculating
		/// a signature for later verification. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
		/// the data on the fly as well.
		/// </summary>
		/// <returns> an OutputStream </returns>
		OutputStream getOutputStream();

		/// <param name="expected"> expected value of the signature on the data. </param>
		/// <returns> true if the signature verifies, false otherwise </returns>
		bool verify(byte[] expected);
	}
}