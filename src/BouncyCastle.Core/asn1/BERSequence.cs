using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Indefinite length SEQUENCE of objects.
	/// <para>
	/// Length field has value 0x80, and the sequence ends with two bytes of: 0x00, 0x00.
	/// </para>
	/// </para><para>
	/// For X.690 syntax rules, see <seealso cref="ASN1Sequence"/>.
	/// </p>
	/// </summary>
	public class BERSequence : ASN1Sequence
	{
		/// <summary>
		/// Create an empty sequence
		/// </summary>
		public BERSequence()
		{
		}

		/// <summary>
		/// Create a sequence containing one object
		/// </summary>
		public BERSequence(ASN1Encodable obj) : base(obj)
		{
		}

		/// <summary>
		/// Create a sequence containing a vector of objects.
		/// </summary>
		public BERSequence(ASN1EncodableVector v) : base(v)
		{
		}

		/// <summary>
		/// Create a sequence containing an array of objects.
		/// </summary>
		public BERSequence(ASN1Encodable[] array) : base(array)
		{
		}

		public override int encodedLength()
		{
			int length = 0;
			for (Enumeration e = getObjects(); e.hasMoreElements();)
			{
				length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
			}

			return 2 + length + 2;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.write(BERTags_Fields.SEQUENCE | BERTags_Fields.CONSTRUCTED);
			@out.write(0x80);

			Enumeration e = getObjects();
			while (e.hasMoreElements())
			{
				@out.writeObject((ASN1Encodable)e.nextElement());
			}

			@out.write(0x00);
			@out.write(0x00);
		}
	}

}