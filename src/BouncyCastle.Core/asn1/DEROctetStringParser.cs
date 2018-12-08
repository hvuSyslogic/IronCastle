using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser for DER encoded OCTET STRINGS
	/// </summary>
	public class DEROctetStringParser : ASN1OctetStringParser
	{
		private DefiniteLengthInputStream stream;

		public DEROctetStringParser(DefiniteLengthInputStream stream)
		{
			this.stream = stream;
		}

		/// <summary>
		/// Return an InputStream representing the contents of the OCTET STRING.
		/// </summary>
		/// <returns> an InputStream with its source as the OCTET STRING content. </returns>
		public virtual InputStream getOctetStream()
		{
			return stream;
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the OCTET STRING.
		/// </summary>
		/// <returns> a DEROctetString. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return new DEROctetString(stream.toByteArray());
		}

		/// <summary>
		/// Return an DEROctetString representing this parser and its contents.
		/// </summary>
		/// <returns> an DEROctetString </returns>
		public virtual ASN1Primitive toASN1Primitive()
		{
			try
			{
				return getLoadedObject();
			}
			catch (IOException e)
			{
				throw new ASN1ParsingException("IOException converting stream to byte array: " + e.Message, e);
			}
		}
	}

}