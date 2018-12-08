using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.cms
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652">RFC 5652</a> CMS attribute OID constants.
	/// and <a href="http://tools.ietf.org/html/rfc6211">RFC 6211</a> Algorithm Identifier Protection Attribute.
	/// <pre>
	/// contentType      ::= 1.2.840.113549.1.9.3
	/// messageDigest    ::= 1.2.840.113549.1.9.4
	/// signingTime      ::= 1.2.840.113549.1.9.5
	/// counterSignature ::= 1.2.840.113549.1.9.6
	/// 
	/// contentHint      ::= 1.2.840.113549.1.9.16.2.4
	/// cmsAlgorithmProtect := 1.2.840.113549.1.9.52
	/// </pre>
	/// </summary>

	public interface CMSAttributes
	{
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.3 </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.4 </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.5 </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.6 </summary>
		/// <summary>
		/// PKCS#9: 1.2.840.113549.1.9.16.6.2.4 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a> </summary>

	}

	public static class CMSAttributes_Fields
	{
		public static readonly ASN1ObjectIdentifier contentType = PKCSObjectIdentifiers_Fields.pkcs_9_at_contentType;
		public static readonly ASN1ObjectIdentifier messageDigest = PKCSObjectIdentifiers_Fields.pkcs_9_at_messageDigest;
		public static readonly ASN1ObjectIdentifier signingTime = PKCSObjectIdentifiers_Fields.pkcs_9_at_signingTime;
		public static readonly ASN1ObjectIdentifier counterSignature = PKCSObjectIdentifiers_Fields.pkcs_9_at_counterSignature;
		public static readonly ASN1ObjectIdentifier contentHint = PKCSObjectIdentifiers_Fields.id_aa_contentHint;
		public static readonly ASN1ObjectIdentifier cmsAlgorithmProtect = PKCSObjectIdentifiers_Fields.id_aa_cmsAlgorithmProtect;
	}

}