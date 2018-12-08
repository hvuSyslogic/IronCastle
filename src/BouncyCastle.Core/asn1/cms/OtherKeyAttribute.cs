using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>: OtherKeyAttribute object.
	/// <para>
	/// <pre>
	/// OtherKeyAttribute ::= SEQUENCE {
	///     keyAttrId OBJECT IDENTIFIER,
	///     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class OtherKeyAttribute : ASN1Object
	{
		private ASN1ObjectIdentifier keyAttrId;
		private ASN1Encodable keyAttr;

		/// <summary>
		/// Return an OtherKeyAttribute object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="OtherKeyAttribute"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with OtherKeyAttribute structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OtherKeyAttribute getInstance(object o)
		{
			if (o is OtherKeyAttribute)
			{
				return (OtherKeyAttribute)o;
			}

			if (o != null)
			{
				return new OtherKeyAttribute(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private OtherKeyAttribute(ASN1Sequence seq)
		{
			keyAttrId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			keyAttr = seq.getObjectAt(1);
		}

		public OtherKeyAttribute(ASN1ObjectIdentifier keyAttrId, ASN1Encodable keyAttr)
		{
			this.keyAttrId = keyAttrId;
			this.keyAttr = keyAttr;
		}

		public virtual ASN1ObjectIdentifier getKeyAttrId()
		{
			return keyAttrId;
		}

		public virtual ASN1Encodable getKeyAttr()
		{
			return keyAttr;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyAttrId);
			v.add(keyAttr);

			return new DERSequence(v);
		}
	}

}