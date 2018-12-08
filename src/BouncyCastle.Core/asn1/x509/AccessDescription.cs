using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The AccessDescription object.
	/// <pre>
	/// AccessDescription  ::=  SEQUENCE {
	///       accessMethod          OBJECT IDENTIFIER,
	///       accessLocation        GeneralName  }
	/// </pre>
	/// </summary>
	public class AccessDescription : ASN1Object
	{
		public static readonly ASN1ObjectIdentifier id_ad_caIssuers = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2");

		public static readonly ASN1ObjectIdentifier id_ad_ocsp = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");

		internal ASN1ObjectIdentifier accessMethod = null;
		internal GeneralName accessLocation = null;

		public static AccessDescription getInstance(object obj)
		{
			if (obj is AccessDescription)
			{
				return (AccessDescription)obj;
			}
			else if (obj != null)
			{
				return new AccessDescription(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private AccessDescription(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("wrong number of elements in sequence");
			}

			accessMethod = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			accessLocation = GeneralName.getInstance(seq.getObjectAt(1));
		}

		/// <summary>
		/// create an AccessDescription with the oid and location provided.
		/// </summary>
		public AccessDescription(ASN1ObjectIdentifier oid, GeneralName location)
		{
			accessMethod = oid;
			accessLocation = location;
		}

		/// 
		/// <returns> the access method. </returns>
		public virtual ASN1ObjectIdentifier getAccessMethod()
		{
			return accessMethod;
		}

		/// 
		/// <returns> the access location </returns>
		public virtual GeneralName getAccessLocation()
		{
			return accessLocation;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector accessDescription = new ASN1EncodableVector();

			accessDescription.add(accessMethod);
			accessDescription.add(accessLocation);

			return new DERSequence(accessDescription);
		}

		public override string ToString()
		{
			return ("AccessDescription: Oid(" + this.accessMethod.getId() + ")");
		}
	}

}