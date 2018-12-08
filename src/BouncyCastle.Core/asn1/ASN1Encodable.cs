namespace org.bouncycastle.asn1
{
	/// <summary>
	/// Basic interface to produce serialisers for ASN.1 encodings.
	/// </summary>
	public interface ASN1Encodable
	{
		/// <summary>
		/// Return an object, possibly constructed, of ASN.1 primitives </summary>
		/// <returns> an ASN.1 primitive. </returns>
		ASN1Primitive toASN1Primitive();
	}

}