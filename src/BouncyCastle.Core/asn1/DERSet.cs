using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A DER encoded SET object
	/// <para>
	/// For X.690 syntax rules, see <seealso cref="ASN1Set"/>.
	/// </para>
	/// </para><para>
	/// For short: Constructing this form does sort the supplied elements,
	/// and the sorting happens also before serialization (if necesssary).
	/// This is different from the way <seealso cref="BERSet"/>,<seealso cref="DLSet"/> does things.
	/// </p>
	/// </summary>
	public class DERSet : ASN1Set
	{
		private int bodyLength = -1;

		/// <summary>
		/// create an empty set
		/// </summary>
		public DERSet()
		{
		}

		/// <summary>
		/// create a set containing one object </summary>
		/// <param name="obj"> the object to go in the set </param>
		public DERSet(ASN1Encodable obj) : base(obj)
		{
		}

		/// <summary>
		/// create a set containing a vector of objects. </summary>
		/// <param name="v"> the vector of objects to make up the set. </param>
		public DERSet(ASN1EncodableVector v) : base(v, true)
		{
		}

		/// <summary>
		/// create a set containing an array of objects. </summary>
		/// <param name="a"> the array of objects to make up the set. </param>
		public DERSet(ASN1Encodable[] a) : base(a, true)
		{
		}

		public DERSet(ASN1EncodableVector v, bool doSort) : base(v, doSort)
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
		 * ASN.1 descriptions given. Rather than just outputting SET,
		 * we also have to specify CONSTRUCTED, and the objects length.
		 */
		public override void encode(ASN1OutputStream @out)
		{
			ASN1OutputStream dOut = @out.getDERSubStream();
			int length = getBodyLength();

			@out.write(BERTags_Fields.SET | BERTags_Fields.CONSTRUCTED);
			@out.writeLength(length);

			for (Enumeration e = this.getObjects(); e.hasMoreElements();)
			{
				object obj = e.nextElement();

				dOut.writeObject((ASN1Encodable)obj);
			}
		}
	}

}