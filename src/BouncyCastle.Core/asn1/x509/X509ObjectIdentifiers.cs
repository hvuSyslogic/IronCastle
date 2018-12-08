namespace org.bouncycastle.asn1.x509
{

	public interface X509ObjectIdentifiers
	{

		/// <summary>
		/// Subject RDN components: commonName = 2.5.4.3 </summary>
		/// <summary>
		/// Subject RDN components: countryName = 2.5.4.6 </summary>
		/// <summary>
		/// Subject RDN components: localityName = 2.5.4.7 </summary>
		/// <summary>
		/// Subject RDN components: stateOrProvinceName = 2.5.4.8 </summary>
		/// <summary>
		/// Subject RDN components: organization = 2.5.4.10 </summary>
		/// <summary>
		/// Subject RDN components: organizationalUnitName = 2.5.4.11 </summary>

		/// <summary>
		/// Subject RDN components: telephone_number = 2.5.4.20 </summary>
		/// <summary>
		/// Subject RDN components: name = 2.5.4.41 </summary>

		/// <summary>
		/// id-SHA1 OBJECT IDENTIFIER ::=    
		///   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }
		/// <para>
		/// OID: 1.3.14.3.2.27
		/// </para>
		/// </summary>

		/// <summary>
		/// ripemd160 OBJECT IDENTIFIER ::=
		///      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) hashAlgorithm(2) RIPEMD-160(1)}
		/// <para>
		/// OID: 1.3.36.3.2.1
		/// </para>
		/// </summary>

		/// <summary>
		/// ripemd160WithRSAEncryption OBJECT IDENTIFIER ::=
		///      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) signatureAlgorithm(3) rsaSignature(1) rsaSignatureWithripemd160(2) }
		/// <para>
		/// OID: 1.3.36.3.3.1.2
		/// </para>
		/// </summary>


		/// <summary>
		/// OID: 2.5.8.1.1 </summary>

		/// <summary>
		/// id-pkix OID: 1.3.6.1.5.5.7
		/// </summary>

		/// <summary>
		/// private internet extensions; OID = 1.3.6.1.5.5.7.1
		/// </summary>

		/// <summary>
		/// ISO ARC for standard certificate and CRL extensions
		/// <para>
		/// OID: 2.5.29
		/// </para>
		/// </summary>

		/// <summary>
		/// id-pkix OID:         1.3.6.1.5.5.7.48 </summary>
		/// <summary>
		/// id-ad-caIssuers OID: 1.3.6.1.5.5.7.48.2 </summary>
		/// <summary>
		/// id-ad-ocsp OID:      1.3.6.1.5.5.7.48.1 </summary>

		/// <summary>
		/// OID for ocsp uri in AuthorityInformationAccess extension </summary>
		/// <summary>
		/// OID for crl uri in AuthorityInformationAccess extension </summary>
	}

	public static class X509ObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier commonName = new ASN1ObjectIdentifier("2.5.4.3").intern();
		public static readonly ASN1ObjectIdentifier countryName = new ASN1ObjectIdentifier("2.5.4.6").intern();
		public static readonly ASN1ObjectIdentifier localityName = new ASN1ObjectIdentifier("2.5.4.7").intern();
		public static readonly ASN1ObjectIdentifier stateOrProvinceName = new ASN1ObjectIdentifier("2.5.4.8").intern();
		public static readonly ASN1ObjectIdentifier organization = new ASN1ObjectIdentifier("2.5.4.10").intern();
		public static readonly ASN1ObjectIdentifier organizationalUnitName = new ASN1ObjectIdentifier("2.5.4.11").intern();
		public static readonly ASN1ObjectIdentifier id_at_telephoneNumber = new ASN1ObjectIdentifier("2.5.4.20").intern();
		public static readonly ASN1ObjectIdentifier id_at_name = new ASN1ObjectIdentifier("2.5.4.41").intern();
		public static readonly ASN1ObjectIdentifier id_at_organizationIdentifier = new ASN1ObjectIdentifier("2.5.4.97").intern();
		public static readonly ASN1ObjectIdentifier id_SHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26").intern();
		public static readonly ASN1ObjectIdentifier ripemd160 = new ASN1ObjectIdentifier("1.3.36.3.2.1").intern();
		public static readonly ASN1ObjectIdentifier ripemd160WithRSAEncryption = new ASN1ObjectIdentifier("1.3.36.3.3.1.2").intern();
		public static readonly ASN1ObjectIdentifier id_ea_rsa = new ASN1ObjectIdentifier("2.5.8.1.1").intern();
		public static readonly ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
		public static readonly ASN1ObjectIdentifier id_pe = id_pkix.branch("1");
		public static readonly ASN1ObjectIdentifier id_ce = new ASN1ObjectIdentifier("2.5.29");
		public static readonly ASN1ObjectIdentifier id_ad = id_pkix.branch("48");
		public static readonly ASN1ObjectIdentifier id_ad_caIssuers = id_ad.branch("2").intern();
		public static readonly ASN1ObjectIdentifier id_ad_ocsp = id_ad.branch("1").intern();
		public static readonly ASN1ObjectIdentifier ocspAccessMethod = id_ad_ocsp;
		public static readonly ASN1ObjectIdentifier crlAccessMethod = id_ad_caIssuers;
	}

}