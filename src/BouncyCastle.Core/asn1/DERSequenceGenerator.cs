using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A stream generator for DER SEQUENCEs
	/// </summary>
	public class DERSequenceGenerator : DERGenerator
	{
		private readonly ByteArrayOutputStream _bOut = new ByteArrayOutputStream();

		/// <summary>
		/// Use the passed in stream as the target for the generator.
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public DERSequenceGenerator(OutputStream @out) : base(@out)
		{
		}

		/// <summary>
		/// Use the passed in stream as the target for the generator, writing out the header tag
		/// for a tagged constructed SEQUENCE (possibly implicit).
		/// </summary>
		/// <param name="out"> target stream </param>
		/// <param name="tagNo"> the tag number to introduce </param>
		/// <param name="isExplicit"> true if this is an explicitly tagged object, false otherwise. </param>
		/// <exception cref="IOException"> if the target stream cannot be written to. </exception>
		public DERSequenceGenerator(OutputStream @out, int tagNo, bool isExplicit) : base(@out, tagNo, isExplicit)
		{
		}

		/// <summary>
		/// Add an object to the SEQUENCE being generated.
		/// </summary>
		/// <param name="object"> an ASN.1 encodable object to add. </param>
		/// <exception cref="IOException"> if the target stream cannot be written to or the object cannot be encoded. </exception>
		public virtual void addObject(ASN1Encodable @object)
		{
			@object.toASN1Primitive().encode(new DEROutputStream(_bOut));
		}

		/// <summary>
		/// Return the target stream for the SEQUENCE.
		/// </summary>
		/// <returns>  the OutputStream the SEQUENCE is being written to. </returns>
		public override OutputStream getRawOutputStream()
		{
			return _bOut;
		}

		/// <summary>
		/// Close of the generator, writing out the SEQUENCE.
		/// </summary>
		/// <exception cref="IOException"> if the target stream cannot be written. </exception>
		public virtual void close()
		{
			writeDEREncoded(BERTags_Fields.CONSTRUCTED | BERTags_Fields.SEQUENCE, _bOut.toByteArray());
		}
	}

}