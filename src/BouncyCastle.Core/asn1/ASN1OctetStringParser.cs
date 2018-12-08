using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A basic parser for an OCTET STRING object
	/// </summary>
	public interface ASN1OctetStringParser : ASN1Encodable, InMemoryRepresentable
	{
		/// <summary>
		/// Return the content of the OCTET STRING as an InputStream.
		/// </summary>
		/// <returns> an InputStream representing the OCTET STRING's content. </returns>
		InputStream getOctetStream();
	}

}