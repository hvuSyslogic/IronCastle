using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser DER EXTERNAL tagged objects.
	/// </summary>
	public class DERExternalParser : ASN1Encodable, InMemoryRepresentable
	{
		private ASN1StreamParser _parser;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="parser"> the underlying parser to read the DER EXTERNAL from. </param>
		public DERExternalParser(ASN1StreamParser parser)
		{
			this._parser = parser;
		}

		public virtual ASN1Encodable readObject()
		{
			return _parser.readObject();
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the EXTERNAL object.
		/// </summary>
		/// <returns> a DERExternal. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			try
			{
				return new DLExternal(_parser.readVector());
			}
			catch (IllegalArgumentException e)
			{
				throw new ASN1Exception(e.getMessage(), e);
			}
		}

		/// <summary>
		/// Return an DERExternal representing this parser and its contents.
		/// </summary>
		/// <returns> an DERExternal </returns>
		public virtual ASN1Primitive toASN1Primitive()
		{
			try
			{
				return getLoadedObject();
			}
			catch (IOException ioe)
			{
				throw new ASN1ParsingException("unable to get DER object", ioe);
			}
			catch (IllegalArgumentException ioe)
			{
				throw new ASN1ParsingException("unable to get DER object", ioe);
			}
		}
	}
}