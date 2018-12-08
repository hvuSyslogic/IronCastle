using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// The DLSequence encodes a SEQUENCE using definite length form.
	/// </summary>
	public class DLSequence : ASN1Sequence
	{
		private int bodyLength = -1;

		/// <summary>
		/// Create an empty sequence
		/// </summary>
		public DLSequence()
		{
		}

		/// <summary>
		/// create a sequence containing one object </summary>
		/// <param name="obj"> the object to go in the sequence. </param>
		public DLSequence(ASN1Encodable obj) : base(obj)
		{
		}

		/// <summary>
		/// create a sequence containing a vector of objects. </summary>
		/// <param name="v"> the vector of objects to make up the sequence. </param>
		public DLSequence(ASN1EncodableVector v) : base(v)
		{
		}

		/// <summary>
		/// create a sequence containing an array of objects. </summary>
		/// <param name="array"> the array of objects to make up the sequence. </param>
		public DLSequence(ASN1Encodable[] array) : base(array)
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

					length += ((ASN1Encodable)obj).toASN1Primitive().toDLObject().encodedLength();
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

		/// <summary>
		/// A note on the implementation:
		/// <para>
		/// As DL requires the constructed, definite-length model to
		/// be used for structured types, this varies slightly from the
		/// ASN.1 descriptions given. Rather than just outputting SEQUENCE,
		/// we also have to specify CONSTRUCTED, and the objects length.
		/// </para>
		/// </summary>
		public override void encode(ASN1OutputStream @out)
		{
			ASN1OutputStream dOut = @out.getDLSubStream();
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