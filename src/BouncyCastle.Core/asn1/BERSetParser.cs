using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser for indefinite-length SETs.
	/// </summary>
	public class BERSetParser : ASN1SetParser
	{
		private ASN1StreamParser _parser;

		public BERSetParser(ASN1StreamParser parser)
		{
			this._parser = parser;
		}

		/// <summary>
		/// Read the next object in the SET.
		/// </summary>
		/// <returns> the next object in the SET, null if there are no more. </returns>
		/// <exception cref="IOException"> if there is an issue reading the underlying stream. </exception>
		public virtual ASN1Encodable readObject()
		{
			return _parser.readObject();
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the SET.
		/// </summary>
		/// <returns> a BERSet. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return new BERSet(_parser.readVector());
		}

		/// <summary>
		/// Return an BERSet representing this parser and its contents.
		/// </summary>
		/// <returns> an BERSet </returns>
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