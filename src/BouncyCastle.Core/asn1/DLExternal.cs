using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Class representing the Definite-Length-type External
	/// </summary>
	public class DLExternal : ASN1External
	{
		/// <summary>
		/// Construct a Definite-Length EXTERNAL object, the input encoding vector must have exactly two elements on it.
		/// <para>
		/// Acceptable input formats are:
		/// <ul>
		/// <li> <seealso cref="ASN1ObjectIdentifier"/> + data <seealso cref="DERTaggedObject"/> (direct reference form)</li>
		/// <li> <seealso cref="ASN1Integer"/> + data <seealso cref="DERTaggedObject"/> (indirect reference form)</li>
		/// <li> Anything but <seealso cref="DERTaggedObject"/> + data <seealso cref="DERTaggedObject"/> (data value form)</li>
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IllegalArgumentException"> if input size is wrong, or </exception>
		public DLExternal(ASN1EncodableVector vector) : base(vector)
		{
		}

		/// <summary>
		/// Creates a new instance of DERExternal
		/// See X.690 for more informations about the meaning of these parameters </summary>
		/// <param name="directReference"> The direct reference or <code>null</code> if not set. </param>
		/// <param name="indirectReference"> The indirect reference or <code>null</code> if not set. </param>
		/// <param name="dataValueDescriptor"> The data value descriptor or <code>null</code> if not set. </param>
		/// <param name="externalData"> The external data in its encoded form. </param>
		public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, DERTaggedObject externalData) : this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.toASN1Primitive())
		{
		}

		/// <summary>
		/// Creates a new instance of Definite-Length External.
		/// See X.690 for more informations about the meaning of these parameters </summary>
		/// <param name="directReference"> The direct reference or <code>null</code> if not set. </param>
		/// <param name="indirectReference"> The indirect reference or <code>null</code> if not set. </param>
		/// <param name="dataValueDescriptor"> The data value descriptor or <code>null</code> if not set. </param>
		/// <param name="encoding"> The encoding to be used for the external data </param>
		/// <param name="externalData"> The external data </param>
		public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData) : base(directReference, indirectReference, dataValueDescriptor, encoding, externalData)
		{
		}

		public override int encodedLength()
		{
			return this.getEncoded().Length;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
		 */
		public override void encode(ASN1OutputStream @out)
		{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			if (directReference != null)
			{
				baos.write(directReference.getEncoded(ASN1Encoding_Fields.DL));
			}
			if (indirectReference != null)
			{
				baos.write(indirectReference.getEncoded(ASN1Encoding_Fields.DL));
			}
			if (dataValueDescriptor != null)
			{
				baos.write(dataValueDescriptor.getEncoded(ASN1Encoding_Fields.DL));
			}
			DERTaggedObject obj = new DERTaggedObject(true, encoding, externalContent);
			baos.write(obj.getEncoded(ASN1Encoding_Fields.DL));
			@out.writeEncoded(BERTags_Fields.CONSTRUCTED, BERTags_Fields.EXTERNAL, baos.toByteArray());
		}
	}

}