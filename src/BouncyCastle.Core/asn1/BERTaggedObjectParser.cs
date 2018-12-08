using System.IO;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Parser for indefinite-length tagged objects.
	/// </summary>
	public class BERTaggedObjectParser : ASN1TaggedObjectParser
	{
		private bool _constructed;
		private int _tagNumber;
		private ASN1StreamParser _parser;

		public BERTaggedObjectParser(bool constructed, int tagNumber, ASN1StreamParser parser)
		{
			_constructed = constructed;
			_tagNumber = tagNumber;
			_parser = parser;
		}

		/// <summary>
		/// Return true if this tagged object is marked as constructed.
		/// </summary>
		/// <returns> true if constructed, false otherwise. </returns>
		public virtual bool isConstructed()
		{
			return _constructed;
		}

		/// <summary>
		/// Return the tag number associated with this object.
		/// </summary>
		/// <returns> the tag number. </returns>
		public virtual int getTagNo()
		{
			return _tagNumber;
		}

		/// <summary>
		/// Return an object parser for the contents of this tagged object.
		/// </summary>
		/// <param name="tag"> the actual tag number of the object (needed if implicit). </param>
		/// <param name="isExplicit"> true if the contained object was explicitly tagged, false if implicit. </param>
		/// <returns> an ASN.1 encodable object parser. </returns>
		/// <exception cref="IOException"> if there is an issue building the object parser from the stream. </exception>
		public virtual ASN1Encodable getObjectParser(int tag, bool isExplicit)
		{
			if (isExplicit)
			{
				if (!_constructed)
				{
					throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
				}
				return _parser.readObject();
			}

			return _parser.readImplicit(_constructed, tag);
		}

		/// <summary>
		/// Return an in-memory, encodable, representation of the tagged object.
		/// </summary>
		/// <returns> an ASN1TaggedObject. </returns>
		/// <exception cref="IOException"> if there is an issue loading the data. </exception>
		public virtual ASN1Primitive getLoadedObject()
		{
			return _parser.readTaggedObject(_constructed, _tagNumber);
		}

		/// <summary>
		/// Return an ASN1TaggedObject representing this parser and its contents.
		/// </summary>
		/// <returns> an ASN1TaggedObject </returns>
		public virtual ASN1Primitive toASN1Primitive()
		{
			try
			{
				return this.getLoadedObject();
			}
			catch (IOException e)
			{
				throw new ASN1ParsingException(e.Message);
			}
		}
	}
}