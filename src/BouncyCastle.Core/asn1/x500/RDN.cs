namespace org.bouncycastle.asn1.x500
{

	/// <summary>
	/// Holding class for a single Relative Distinguished Name (RDN).
	/// </summary>
	public class RDN : ASN1Object
	{
		private ASN1Set values;

		private RDN(ASN1Set values)
		{
			this.values = values;
		}

		public static RDN getInstance(object obj)
		{
			if (obj is RDN)
			{
				return (RDN)obj;
			}
			else if (obj != null)
			{
				return new RDN(ASN1Set.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Create a single valued RDN.
		/// </summary>
		/// <param name="oid"> RDN type. </param>
		/// <param name="value"> RDN value. </param>
		public RDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(oid);
			v.add(value);

			this.values = new DERSet(new DERSequence(v));
		}

		public RDN(AttributeTypeAndValue attrTAndV)
		{
			this.values = new DERSet(attrTAndV);
		}

		/// <summary>
		/// Create a multi-valued RDN.
		/// </summary>
		/// <param name="aAndVs"> attribute type/value pairs making up the RDN </param>
		public RDN(AttributeTypeAndValue[] aAndVs)
		{
			this.values = new DERSet(aAndVs);
		}

		public virtual bool isMultiValued()
		{
			return this.values.size() > 1;
		}

		/// <summary>
		/// Return the number of AttributeTypeAndValue objects in this RDN,
		/// </summary>
		/// <returns> size of RDN, greater than 1 if multi-valued. </returns>
		public virtual int size()
		{
			return this.values.size();
		}

		public virtual AttributeTypeAndValue getFirst()
		{
			if (this.values.size() == 0)
			{
				return null;
			}

			return AttributeTypeAndValue.getInstance(this.values.getObjectAt(0));
		}

		public virtual AttributeTypeAndValue[] getTypesAndValues()
		{
			AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = AttributeTypeAndValue.getInstance(values.getObjectAt(i));
			}

			return tmp;
		}

		/// <summary>
		/// <pre>
		/// RelativeDistinguishedName ::=
		///                     SET OF AttributeTypeAndValue
		/// 
		/// AttributeTypeAndValue ::= SEQUENCE {
		///        type     AttributeType,
		///        value    AttributeValue }
		/// </pre> </summary>
		/// <returns> this object as its ASN1Primitive type </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return values;
		}
	}

}