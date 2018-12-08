using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The AuthorityInformationAccess object.
	/// <pre>
	/// id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
	/// 
	/// AuthorityInfoAccessSyntax  ::=
	///      SEQUENCE SIZE (1..MAX) OF AccessDescription
	/// AccessDescription  ::=  SEQUENCE {
	///       accessMethod          OBJECT IDENTIFIER,
	///       accessLocation        GeneralName  }
	/// 
	/// id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
	/// id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
	/// id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
	/// </pre>
	/// </summary>
	public class AuthorityInformationAccess : ASN1Object
	{
		private AccessDescription[] descriptions;

		public static AuthorityInformationAccess getInstance(object obj)
		{
			if (obj is AuthorityInformationAccess)
			{
				return (AuthorityInformationAccess)obj;
			}

			if (obj != null)
			{
				return new AuthorityInformationAccess(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static AuthorityInformationAccess fromExtensions(Extensions extensions)
		{
			 return AuthorityInformationAccess.getInstance(extensions.getExtensionParsedValue(Extension.authorityInfoAccess));
		}

		private AuthorityInformationAccess(ASN1Sequence seq)
		{
			if (seq.size() < 1)
			{
				throw new IllegalArgumentException("sequence may not be empty");
			}

			descriptions = new AccessDescription[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
			}
		}

		public AuthorityInformationAccess(AccessDescription description) : this(new AccessDescription[]{description})
		{
		}

		public AuthorityInformationAccess(AccessDescription[] descriptions)
		{
			this.descriptions = new AccessDescription[descriptions.Length];
			JavaSystem.arraycopy(descriptions, 0, this.descriptions, 0, descriptions.Length);
		}

		/// <summary>
		/// create an AuthorityInformationAccess with the oid and location provided.
		/// </summary>
		public AuthorityInformationAccess(ASN1ObjectIdentifier oid, GeneralName location) : this(new AccessDescription(oid, location))
		{
		}

		/// 
		/// <returns> the access descriptions contained in this object. </returns>
		public virtual AccessDescription[] getAccessDescriptions()
		{
			return descriptions;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();

			for (int i = 0; i != descriptions.Length; i++)
			{
				vec.add(descriptions[i]);
			}

			return new DERSequence(vec);
		}

		public override string ToString()
		{
			return ("AuthorityInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")");
		}
	}

}