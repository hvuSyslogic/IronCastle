using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Definite length SEQUENCE, encoding tells explicit number of bytes
	/// that the content of this sequence occupies.
	/// <para>
	/// For X.690 syntax rules, see <seealso cref="ASN1Sequence"/>.
	/// </para>
	/// </summary>
	public class DERSequence : ASN1Sequence
	{
		private int bodyLength = -1;

		/// <summary>
		/// Create an empty sequence
		/// </summary>
		public DERSequence()
		{
		}

		/// <summary>
		/// Create a sequence containing one object </summary>
		/// <param name="obj"> the object to go in the sequence. </param>
		public DERSequence(ASN1Encodable obj) : base(obj)
		{
		}

		/// <summary>
		/// Create a sequence containing a vector of objects. </summary>
		/// <param name="v"> the vector of objects to make up the sequence. </param>
		public DERSequence(ASN1EncodableVector v) : base(v)
		{
		}

		/// <summary>
		/// Create a sequence containing an array of objects. </summary>
		/// <param name="array"> the array of objects to make up the sequence. </param>
		public DERSequence(ASN1Encodable[] array) : base(array)
		{
		}

		private int getBodyLength()
		{
			if (bodyLength < 0)
			{
				int length = 0;

				for (Enumeration e = this.getObjects(); e.hasMoreElements();)
				{
					object obj = e.nextElement();

					length += ((ASN1Encodable)obj).toASN1Primitive().toDERObject().encodedLength();
				}

				bodyLength = length;
			}

			return bodyLength;
		}

		public override int encodedLength()
		{
			int length = getBodyLength();

			return 1 + StreamUtil.calculateBodyLength(length) + length;
		}

		/*
		 * A note on the implementation:
		 * <p>
		 * As DER requires the constructed, definite-length model to
		 * be used for structured types, this varies slightly from the
		 * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
		 * we also have to specify CONSTRUCTED, and the objects length.
		 */
		public override void encode(ASN1OutputStream @out)
		{
			ASN1OutputStream dOut = @out.getDERSubStream();
			int length = getBodyLength();

			@out.write(BERTags_Fields.SEQUENCE | BERTags_Fields.CONSTRUCTED);
			@out.writeLength(length);

			for (Enumeration e = this.getObjects(); e.hasMoreElements();)
			{
				object obj = e.nextElement();

				dOut.writeObject((ASN1Encodable)obj);
			}
		}
	}

}