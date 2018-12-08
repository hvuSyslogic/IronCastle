using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Interface implemented by objects that can be converted from streaming to in-memory objects.
	/// </summary>
	public interface InMemoryRepresentable
	{
		/// <summary>
		/// Get the in-memory representation of the ASN.1 object. </summary>
		/// <returns> an ASN1Primitive representing the loaded object. </returns>
		/// <exception cref="IOException"> for bad input data. </exception>
		ASN1Primitive getLoadedObject();
	}

}