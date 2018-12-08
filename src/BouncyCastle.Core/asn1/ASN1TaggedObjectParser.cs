using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Interface for the parsing of a generic tagged ASN.1 object.
	/// </summary>
	public interface ASN1TaggedObjectParser : ASN1Encodable, InMemoryRepresentable
	{
		/// <summary>
		/// Return the tag number associated with the underlying tagged object. </summary>
		/// <returns> the object's tag number. </returns>
		int getTagNo();

		/// <summary>
		/// Return a parser for the actual object tagged.
		/// </summary>
		/// <param name="tag"> the primitive tag value for the object tagged originally. </param>
		/// <param name="isExplicit"> true if the tagging was done explicitly. </param>
		/// <returns> a parser for the tagged object. </returns>
		/// <exception cref="IOException"> if a parser cannot be constructed. </exception>
		ASN1Encodable getObjectParser(int tag, bool isExplicit);
	}

}