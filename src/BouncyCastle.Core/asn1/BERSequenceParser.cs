using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser for indefinite-length SEQUENCEs.
	/// </summary>
	public class BERSequenceParser : ASN1SequenceParser
	{
		private ASN1StreamParser _parser;

		public BERSequenceParser(ASN1StreamParser parser)
		{
			this._parser = parser;
		}

		/// <summary>
		/// Read the next object in the SEQUENCE.
		/// </summary>
		/// <returns> the next object in the SEQUENCE, null if there are no more. </returns>
		/// <exception cref="IOException"> if there is an issue reading the underlying stream. </exception>
		public virtual ASN1Encodable readObject()
		{
			return _parser.readObject();
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the SEQUENCE.
		/// </summary>
		/// <returns> a BERSequence. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return new BERSequence(_parser.readVector());
		}

		/// <summary>
		/// Return an BERSequence representing this parser and its contents.
		/// </summary>
		/// <returns> an BERSequence </returns>
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