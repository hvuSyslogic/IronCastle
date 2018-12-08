namespace org.bouncycastle.asn1.ess
{

	public class ContentIdentifier : ASN1Object
	{
		 internal ASN1OctetString value;

		public static ContentIdentifier getInstance(object o)
		{
			if (o is ContentIdentifier)
			{
				return (ContentIdentifier) o;
			}
			else if (o != null)
			{
				return new ContentIdentifier(ASN1OctetString.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// Create from OCTET STRING whose octets represent the identifier.
		/// </summary>
		private ContentIdentifier(ASN1OctetString value)
		{
			this.value = value;
		}

		/// <summary>
		/// Create from byte array representing the identifier.
		/// </summary>
		public ContentIdentifier(byte[] value) : this(new DEROctetString(value))
		{
		}

		public virtual ASN1OctetString getValue()
		{
			return value;
		}

		/// <summary>
		/// The definition of ContentIdentifier is
		/// <pre>
		/// ContentIdentifier ::=  OCTET STRING
		/// </pre>
		/// id-aa-contentIdentifier OBJECT IDENTIFIER ::= { iso(1)
		///  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		///  smime(16) id-aa(2) 7 }
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}
	}

}