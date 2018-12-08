using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser class for DER SETs.
	/// </summary>
	public class DERSetParser : ASN1SetParser
	{
		private ASN1StreamParser _parser;

		public DERSetParser(ASN1StreamParser parser)
		{
			this._parser = parser;
		}

		/// <summary>
		/// Return the next object in the SET.
		/// </summary>
		/// <returns> next object in SET. </returns>
		/// <exception cref="IOException"> if there is an issue loading the object. </exception>
		public virtual ASN1Encodable readObject()
		{
			return _parser.readObject();
		}

		/// <summary>
		/// Return an in memory, encodable, representation of the SET.
		/// </summary>
		/// <returns> a DERSet. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return new DERSet(_parser.readVector(), false);
		}

		/// <summary>
		/// Return a DERSet representing this parser and its contents.
		/// </summary>
		/// <returns> a DERSet </returns>
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