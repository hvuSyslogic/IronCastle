using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The OtherName object.
	/// <pre>
	/// OtherName ::= SEQUENCE {
	///      type-id    OBJECT IDENTIFIER,
	///      value      [0] EXPLICIT ANY DEFINED BY type-id }
	/// </pre>
	/// </summary>
	public class OtherName : ASN1Object
	{
		private readonly ASN1ObjectIdentifier typeID;
		private readonly ASN1Encodable value;

		/// <summary>
		/// OtherName factory method. </summary>
		/// <param name="obj"> the object used to construct an instance of <code>
		/// OtherName</code>. It must be an instance of <code>OtherName
		/// </code> or <code>ASN1Sequence</code>. </param>
		/// <returns> the instance of <code>OtherName</code> built from the
		/// supplied object. </returns>
		/// <exception cref="IllegalArgumentException"> if the object passed
		/// to the factory is not an instance of <code>OtherName</code> or something that
		/// can be converted into an appropriate <code>ASN1Sequence</code>. </exception>
		public static OtherName getInstance(object obj)
		{

			if (obj is OtherName)
			{
				return (OtherName)obj;
			}
			else if (obj != null)
			{
				return new OtherName(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Base constructor. </summary>
		/// <param name="typeID"> the type of the other name. </param>
		/// <param name="value"> the ANY object that represents the value. </param>
		public OtherName(ASN1ObjectIdentifier typeID, ASN1Encodable value)
		{
			this.typeID = typeID;
			this.value = value;
		}

		private OtherName(ASN1Sequence seq)
		{
			this.typeID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			this.value = ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject(); // explicitly tagged
		}

		public virtual ASN1ObjectIdentifier getTypeID()
		{
			return typeID;
		}

		public virtual ASN1Encodable getValue()
		{
			return value;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(typeID);
			v.add(new DERTaggedObject(true, 0, value));

			return new DERSequence(v);
		}
	}

}