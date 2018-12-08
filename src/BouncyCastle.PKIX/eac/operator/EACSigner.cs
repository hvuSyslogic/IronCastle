namespace org.bouncycastle.eac.@operator
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public interface EACSigner
	{
		ASN1ObjectIdentifier getUsageIdentifier();

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