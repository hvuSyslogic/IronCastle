namespace org.bouncycastle.x509
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.x509.Attribute;

	/// <summary>
	/// Class for carrying the values in an X.509 Attribute. </summary>
	/// @deprecated see X509CertificateHolder class in the PKIX package. 
	public class X509Attribute : ASN1Object
	{
		internal Attribute attr;

		/// <param name="at"> an object representing an attribute. </param>
		public X509Attribute(ASN1Encodable at)
		{
			this.attr = Attribute.getInstance(at);
		}

		/// <summary>
		/// Create an X.509 Attribute with the type given by the passed in oid and
		/// the value represented by an ASN.1 Set containing value.
		/// </summary>
		/// <param name="oid"> type of the attribute </param>
		/// <param name="value"> value object to go into the atribute's value set. </param>
		public X509Attribute(string oid, ASN1Encodable value)
		{
			this.attr = new Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value));
		}

		/// <summary>
		/// Create an X.59 Attribute with the type given by the passed in oid and the
		/// value represented by an ASN.1 Set containing the objects in value.
		/// </summary>
		/// <param name="oid"> type of the attribute </param>
		/// <param name="value"> vector of values to go in the attribute's value set. </param>
		public X509Attribute(string oid, ASN1EncodableVector value)
		{
			this.attr = new Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value));
		}

		public virtual string getOID()
		{
			return attr.getAttrType().getId();
		}

		public virtual ASN1Encodable[] getValues()
		{
			ASN1Set s = attr.getAttrValues();
			ASN1Encodable[] values = new ASN1Encodable[s.size()];

			for (int i = 0; i != s.size(); i++)
			{
				values[i] = (ASN1Encodable)s.getObjectAt(i);
			}

			return values;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return attr.toASN1Primitive();
		}
	}

}