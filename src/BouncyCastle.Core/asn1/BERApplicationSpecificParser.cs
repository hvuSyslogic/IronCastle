using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A parser for indefinite-length ASN.1 ApplicationSpecific objects.
	/// </summary>
	public class BERApplicationSpecificParser : ASN1ApplicationSpecificParser
	{
		private readonly int tag;
		private readonly ASN1StreamParser parser;

		public BERApplicationSpecificParser(int tag, ASN1StreamParser parser)
		{
			this.tag = tag;
			this.parser = parser;
		}

		/// <summary>
		/// Return the object contained in this application specific object, </summary>
		/// <returns> the contained object. </returns>
		/// <exception cref="IOException"> if the underlying stream cannot be read, or does not contain an ASN.1 encoding. </exception>
		public virtual ASN1Encodable readObject()
		{
			return parser.readObject();
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the application specific object.
		/// </summary>
		/// <returns> a BERApplicationSpecific. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			 return new BERApplicationSpecific(tag, parser.readVector());
		}

		/// <summary>
		/// Return a BERApplicationSpecific representing this parser and its contents.
		/// </summary>
		/// <returns> a BERApplicationSpecific </returns>
		public virtual ASN1Primitive toASN1Primitive()
		{
			try
			{
				return getLoadedObject();
			}
			catch (IOException e)
			{
				throw new ASN1ParsingException(e.Message, e);
			}
		}
	}

}