using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#page-14">RFC 5652</a>:
	/// Attribute is a pair of OID (as type identifier) + set of values.
	/// <para>
	/// <pre>
	/// Attribute ::= SEQUENCE {
	///     attrType OBJECT IDENTIFIER,
	///     attrValues SET OF AttributeValue
	/// }
	/// 
	/// AttributeValue ::= ANY
	/// </pre>
	/// </para>
	/// <para>
	/// General rule on values is that same AttributeValue must not be included
	/// multiple times into the set. That is, if the value is a SET OF INTEGERs,
	/// then having same value repeated is wrong: (1, 1), but different values is OK: (1, 2).
	/// Normally the AttributeValue syntaxes are more complicated than that.
	/// </para>
	/// <para>
	/// General rule of Attribute usage is that the <seealso cref="Attributes"/> containers
	/// must not have multiple Attribute:s with same attrType (OID) there.
	/// </para>
	/// </summary>
	public class Attribute : ASN1Object
	{
		private ASN1ObjectIdentifier attrType;
		private ASN1Set attrValues;

		/// <summary>
		/// Return an Attribute object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="Attribute"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with Attribute structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static Attribute getInstance(object o)
		{
			if (o is Attribute)
			{
				return (Attribute)o;
			}

			if (o != null)
			{
				return new Attribute(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private Attribute(ASN1Sequence seq)
		{
			attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			attrValues = (ASN1Set)seq.getObjectAt(1);
		}

		public Attribute(ASN1ObjectIdentifier attrType, ASN1Set attrValues)
		{
			this.attrType = attrType;
			this.attrValues = attrValues;
		}

		public virtual ASN1ObjectIdentifier getAttrType()
		{
			return attrType;
		}

		public virtual ASN1Set getAttrValues()
		{
			return attrValues;
		}

		public virtual ASN1Encodable[] getAttributeValues()
		{
			return attrValues.toArray();
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(attrType);
			v.add(attrValues);

			return new DERSequence(v);
		}
	}

}