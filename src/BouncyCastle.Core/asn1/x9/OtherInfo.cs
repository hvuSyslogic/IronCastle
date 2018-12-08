using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// ASN.1 def for Diffie-Hellman key exchange OtherInfo structure. See
	/// RFC 2631, or X9.42, for further details.
	/// <pre>
	///  OtherInfo ::= SEQUENCE {
	///      keyInfo KeySpecificInfo,
	///      partyAInfo [0] OCTET STRING OPTIONAL,
	///      suppPubInfo [2] OCTET STRING
	///  }
	/// </pre>
	/// </summary>
	public class OtherInfo : ASN1Object
	{
		private KeySpecificInfo keyInfo;
		private ASN1OctetString partyAInfo;
		private ASN1OctetString suppPubInfo;

		public OtherInfo(KeySpecificInfo keyInfo, ASN1OctetString partyAInfo, ASN1OctetString suppPubInfo)
		{
			this.keyInfo = keyInfo;
			this.partyAInfo = partyAInfo;
			this.suppPubInfo = suppPubInfo;
		}

		/// <summary>
		/// Return a OtherInfo object from the passed in object.
		/// </summary>
		/// <param name="obj"> an object for conversion or a byte[]. </param>
		/// <returns> a OtherInfo </returns>
		public static OtherInfo getInstance(object obj)
		{
			if (obj is OtherInfo)
			{
				return (OtherInfo)obj;
			}
			else if (obj != null)
			{
				return new OtherInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private OtherInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			keyInfo = KeySpecificInfo.getInstance(e.nextElement());

			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();

				if (o.getTagNo() == 0)
				{
					partyAInfo = (ASN1OctetString)o.getObject();
				}
				else if (o.getTagNo() == 2)
				{
					suppPubInfo = (ASN1OctetString)o.getObject();
				}
			}
		}

		/// <summary>
		/// Return the key specific info for the KEK/CEK.
		/// </summary>
		/// <returns> the key specific info. </returns>
		public virtual KeySpecificInfo getKeyInfo()
		{
			return keyInfo;
		}

		/// <summary>
		/// PartyA info for key deriviation.
		/// </summary>
		/// <returns> PartyA info. </returns>
		public virtual ASN1OctetString getPartyAInfo()
		{
			return partyAInfo;
		}

		/// <summary>
		/// The length of the KEK to be generated as a 4 byte big endian.
		/// </summary>
		/// <returns> KEK length as a 4 byte big endian in an octet string. </returns>
		public virtual ASN1OctetString getSuppPubInfo()
		{
			return suppPubInfo;
		}

		/// <summary>
		/// Return an ASN.1 primitive representation of this object.
		/// </summary>
		/// <returns> a DERSequence containing the OtherInfo values. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyInfo);

			if (partyAInfo != null)
			{
				v.add(new DERTaggedObject(0, partyAInfo));
			}

			v.add(new DERTaggedObject(2, suppPubInfo));

			return new DERSequence(v);
		}
	}

}