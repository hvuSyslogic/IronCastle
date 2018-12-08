using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser class for DER SEQUENCEs.
	/// </summary>
	public class DERSequenceParser : ASN1SequenceParser
	{
		private ASN1StreamParser _parser;

		public DERSequenceParser(ASN1StreamParser parser)
		{
			this._parser = parser;
		}

		/// <summary>
		/// Return the next object in the SEQUENCE.
		/// </summary>
		/// <returns> next object in SEQUENCE. </returns>
		/// <exception cref="IOException"> if there is an issue loading the object. </exception>
		public virtual ASN1Encodable readObject()
		{
			return _parser.readObject();
		}

		/// <summary>
		/// Return an in memory, encodable, representation of the SEQUENCE.
		/// </summary>
		/// <returns> a DERSequence. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			 return new DERSequence(_parser.readVector());
		}

		/// <summary>
		/// Return a DERSequence representing this parser and its contents.
		/// </summary>
		/// <returns> a DERSequence. </returns>
		public virtual ASN1Primitive toASN1Primitive()
		{
			try
			{
				return getLoadedObject();
			}
			catch (IOException e)
			{
				throw new IllegalStateException(e.Message);
			}
		}
	}

}