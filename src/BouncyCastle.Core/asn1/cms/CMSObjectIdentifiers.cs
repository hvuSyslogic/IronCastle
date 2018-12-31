using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.cms
{
	
	public interface CMSObjectIdentifiers
	{
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.1 </summary>
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.2 </summary>
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.3 </summary>
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.4 </summary>
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.5 </summary>
		/// <summary>
		/// PKCS#7: 1.2.840.113549.1.7.6 </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.16.1.2 -- smime ct authData </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.16.1.9 -- smime ct compressedData </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.16.1.23 -- smime ct authEnvelopedData </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.16.1.31 -- smime ct timestampedData </summary>

		/// <summary>
		/// The other Revocation Info arc
		/// <para>
		/// <pre>
		/// id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
		///        dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
		/// </pre>
		/// </para>
		/// </summary>

		/// <summary>
		/// 1.3.6.1.5.5.7.16.2 </summary>
		/// <summary>
		/// 1.3.6.1.5.5.7.16.4 </summary>
	}

	public static class CMSObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier data = PKCSObjectIdentifiers_Fields.data;
		public static readonly ASN1ObjectIdentifier signedData = PKCSObjectIdentifiers_Fields.signedData;
		public static readonly ASN1ObjectIdentifier envelopedData = PKCSObjectIdentifiers_Fields.envelopedData;
		public static readonly ASN1ObjectIdentifier signedAndEnvelopedData = PKCSObjectIdentifiers_Fields.signedAndEnvelopedData;
		public static readonly ASN1ObjectIdentifier digestedData = PKCSObjectIdentifiers_Fields.digestedData;
		public static readonly ASN1ObjectIdentifier encryptedData = PKCSObjectIdentifiers_Fields.encryptedData;
		public static readonly ASN1ObjectIdentifier authenticatedData = PKCSObjectIdentifiers_Fields.id_ct_authData;
		public static readonly ASN1ObjectIdentifier compressedData = PKCSObjectIdentifiers_Fields.id_ct_compressedData;
		public static readonly ASN1ObjectIdentifier authEnvelopedData = PKCSObjectIdentifiers_Fields.id_ct_authEnvelopedData;
		public static readonly ASN1ObjectIdentifier timestampedData = PKCSObjectIdentifiers_Fields.id_ct_timestampedData;
		public static readonly ASN1ObjectIdentifier id_ri = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16");
		public static readonly ASN1ObjectIdentifier id_ri_ocsp_response = id_ri.branch("2");
		public static readonly ASN1ObjectIdentifier id_ri_scvp = id_ri.branch("4");
	}

}