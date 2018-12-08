using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A stream generator for DER SEQUENCEs
	/// </summary>
	public class BERSequenceGenerator : BERGenerator
	{
		/// <summary>
		/// Use the passed in stream as the target for the generator, writing out the header tag
		/// for a constructed SEQUENCE.
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public BERSequenceGenerator(OutputStream @out) : base(@out)
		{

			writeBERHeader(BERTags_Fields.CONSTRUCTED | BERTags_Fields.SEQUENCE);
		}

		/// <summary>
		/// Use the passed in stream as the target for the generator, writing out the header tag
		/// for a tagged constructed SEQUENCE (possibly implicit).
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <param name="tagNo"> the tag number to introduce </param>
		/// <param name="isExplicit"> true if this is an explicitly tagged object, false otherwise. </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public BERSequenceGenerator(OutputStream @out, int tagNo, bool isExplicit) : base(@out, tagNo, isExplicit)
		{

			writeBERHeader(BERTags_Fields.CONSTRUCTED | BERTags_Fields.SEQUENCE);
		}

		/// <summary>
		/// Add an object to the SEQUENCE being generated.
		/// </summary>
		/// <param name="object"> an ASN.1 encodable object to add. </param>
		/// <exception cref="IOException"> if the target stream cannot be written to or the object cannot be encoded. </exception>
		public virtual void addObject(ASN1Encodable @object)
		{
			@object.toASN1Primitive().encode(new BEROutputStream(_out));
		}

		/// <summary>
		/// Close of the generator, writing out the BER end tag.
		/// </summary>
		/// <exception cref="IOException"> if the target stream cannot be written. </exception>
		public virtual void close()
		{
			writeBEREnd();
		}
	}
}