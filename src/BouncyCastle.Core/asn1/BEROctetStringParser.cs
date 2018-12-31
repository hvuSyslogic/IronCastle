using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util.io;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// A parser for indefinite-length OCTET STRINGs.
	/// </summary>
	public class BEROctetStringParser : ASN1OctetStringParser
	{
		private ASN1StreamParser _parser;

		public BEROctetStringParser(ASN1StreamParser parser)
		{
			_parser = parser;
		}

		/// <summary>
		/// Return an InputStream representing the contents of the OCTET STRING.
		/// </summary>
		/// <returns> an InputStream with its source as the OCTET STRING content. </returns>
		public virtual InputStream getOctetStream()
		{
			return new ConstructedOctetStream(_parser);
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the OCTET STRING.
		/// </summary>
		/// <returns> a BEROctetString. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return new BEROctetString(Streams.readAll(getOctetStream()));
		}

		/// <summary>
		/// Return an BEROctetString representing this parser and its contents.
		/// </summary>
		/// <returns> an BEROctetString </returns>
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