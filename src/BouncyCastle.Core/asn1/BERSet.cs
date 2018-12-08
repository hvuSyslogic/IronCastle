using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Indefinite length <code>SET</code> and <code>SET OF</code> constructs.
	/// <para>
	/// Note: This does not know which syntax the set is!
	/// </para>
	/// </para><para>
	/// Length field has value 0x80, and the set ends with two bytes of: 0x00, 0x00.
	/// </para><para>
	/// For X.690 syntax rules, see <seealso cref="ASN1Set"/>.
	/// </para><para>
	/// In brief: Constructing this form does not sort the supplied elements,
	/// nor does the sorting happen before serialization. This is different
	/// from the way <seealso cref="DERSet"/> does things.
	/// </p>
	/// </summary>
	public class BERSet : ASN1Set
	{
		/// <summary>
		/// Create an empty SET.
		/// </summary>
		public BERSet()
		{
		}

		/// <summary>
		/// Create a SET containing one object.
		/// </summary>
		/// <param name="obj"> - a single object that makes up the set. </param>
		public BERSet(ASN1Encodable obj) : base(obj)
		{
		}

		/// <summary>
		/// Create a SET containing multiple objects. </summary>
		/// <param name="v"> a vector of objects making up the set. </param>
		public BERSet(ASN1EncodableVector v) : base(v, false)
		{
		}

		/// <summary>
		/// Create a SET from an array of objects. </summary>
		/// <param name="a"> an array of ASN.1 objects. </param>
		public BERSet(ASN1Encodable[] a) : base(a, false)
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
			@out.write(BERTags_Fields.SET | BERTags_Fields.CONSTRUCTED);
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