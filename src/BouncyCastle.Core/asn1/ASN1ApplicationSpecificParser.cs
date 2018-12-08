using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Interface to parse ASN.1 ApplicationSpecific objects.
	/// </summary>
	public interface ASN1ApplicationSpecificParser : ASN1Encodable, InMemoryRepresentable
	{
		/// <summary>
		/// Read the next object in the parser.
		/// </summary>
		/// <returns> an ASN1Encodable </returns>
		/// <exception cref="IOException"> on a parsing or decoding error. </exception>
		ASN1Encodable readObject();
	}

}