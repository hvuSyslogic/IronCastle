namespace org.bouncycastle.asn1.misc
{

	public interface MiscObjectIdentifiers
	{
		//
		// Netscape
		//       iso/itu(2) joint-assign(16) us(840) uscompany(1) netscape(113730) cert-extensions(1) }
		//
		/// <summary>
		/// Netscape cert extensions OID base: 2.16.840.1.113730.1
		/// </summary>
		/// <summary>
		/// Netscape cert CertType OID: 2.16.840.1.113730.1.1
		/// </summary>
		/// <summary>
		/// Netscape cert BaseURL OID: 2.16.840.1.113730.1.2
		/// </summary>
		/// <summary>
		/// Netscape cert RevocationURL OID: 2.16.840.1.113730.1.3
		/// </summary>
		/// <summary>
		/// Netscape cert CARevocationURL OID: 2.16.840.1.113730.1.4
		/// </summary>
		/// <summary>
		/// Netscape cert RenewalURL OID: 2.16.840.1.113730.1.7
		/// </summary>
		/// <summary>
		/// Netscape cert CApolicyURL OID: 2.16.840.1.113730.1.8
		/// </summary>
		/// <summary>
		/// Netscape cert SSLServerName OID: 2.16.840.1.113730.1.12
		/// </summary>
		/// <summary>
		/// Netscape cert CertComment OID: 2.16.840.1.113730.1.13
		/// </summary>

		//
		// Verisign
		//       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
		//
		/// <summary>
		/// Verisign OID base: 2.16.840.1.113733.1
		/// </summary>

		/// <summary>
		/// Verisign CZAG (Country,Zip,Age,Gender) Extension OID: 2.16.840.1.113733.1.6.3
		/// </summary>

		/// <summary>
		/// Verisign D&amp;B D-U-N-S number Extension OID: 2.16.840.1.113733.1.6.15
		/// </summary>

		//
		// Novell
		//       iso/itu(2) country(16) us(840) organization(1) novell(113719)
		//
		/// <summary>
		/// Novell OID base: 2.16.840.1.113719
		/// </summary>
		/// <summary>
		/// Novell SecurityAttribs OID: 2.16.840.1.113719.1.9.4.1
		/// </summary>

		//
		// Entrust
		//       iso(1) member-body(16) us(840) nortelnetworks(113533) entrust(7)
		//
		/// <summary>
		/// NortelNetworks Entrust OID base: 1.2.840.113533.7
		/// </summary>
		/// <summary>
		/// NortelNetworks Entrust VersionExtension OID: 1.2.840.113533.7.65.0
		/// </summary>

		/// <summary>
		/// cast5CBC OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) nt(113533) nsn(7) algorithms(66) 10} SEE RFC 2984
		/// </summary>

		//
		// Ascom
		//

		//
		// Peter Gutmann's Cryptlib
		//

		//
		// Blake2b
		//

		//
		// Scrypt
	}

	public static class MiscObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier netscape = new ASN1ObjectIdentifier("2.16.840.1.113730.1");
		public static readonly ASN1ObjectIdentifier netscapeCertType = netscape.branch("1");
		public static readonly ASN1ObjectIdentifier netscapeBaseURL = netscape.branch("2");
		public static readonly ASN1ObjectIdentifier netscapeRevocationURL = netscape.branch("3");
		public static readonly ASN1ObjectIdentifier netscapeCARevocationURL = netscape.branch("4");
		public static readonly ASN1ObjectIdentifier netscapeRenewalURL = netscape.branch("7");
		public static readonly ASN1ObjectIdentifier netscapeCApolicyURL = netscape.branch("8");
		public static readonly ASN1ObjectIdentifier netscapeSSLServerName = netscape.branch("12");
		public static readonly ASN1ObjectIdentifier netscapeCertComment = netscape.branch("13");
		public static readonly ASN1ObjectIdentifier verisign = new ASN1ObjectIdentifier("2.16.840.1.113733.1");
		public static readonly ASN1ObjectIdentifier verisignCzagExtension = verisign.branch("6.3");
		public static readonly ASN1ObjectIdentifier verisignPrivate_6_9 = verisign.branch("6.9");
		public static readonly ASN1ObjectIdentifier verisignOnSiteJurisdictionHash = verisign.branch("6.11");
		public static readonly ASN1ObjectIdentifier verisignBitString_6_13 = verisign.branch("6.13");
		public static readonly ASN1ObjectIdentifier verisignDnbDunsNumber = verisign.branch("6.15");
		public static readonly ASN1ObjectIdentifier verisignIssStrongCrypto = verisign.branch("8.1");
		public static readonly ASN1ObjectIdentifier novell = new ASN1ObjectIdentifier("2.16.840.1.113719");
		public static readonly ASN1ObjectIdentifier novellSecurityAttribs = novell.branch("1.9.4.1");
		public static readonly ASN1ObjectIdentifier entrust = new ASN1ObjectIdentifier("1.2.840.113533.7");
		public static readonly ASN1ObjectIdentifier entrustVersionExtension = entrust.branch("65.0");
		public static readonly ASN1ObjectIdentifier cast5CBC = entrust.branch("66.10");
		public static readonly ASN1ObjectIdentifier as_sys_sec_alg_ideaCBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
		public static readonly ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");
		public static readonly ASN1ObjectIdentifier cryptlib_algorithm = cryptlib.branch("1");
		public static readonly ASN1ObjectIdentifier cryptlib_algorithm_blowfish_ECB = cryptlib_algorithm.branch("1.1");
		public static readonly ASN1ObjectIdentifier cryptlib_algorithm_blowfish_CBC = cryptlib_algorithm.branch("1.2");
		public static readonly ASN1ObjectIdentifier cryptlib_algorithm_blowfish_CFB = cryptlib_algorithm.branch("1.3");
		public static readonly ASN1ObjectIdentifier cryptlib_algorithm_blowfish_OFB = cryptlib_algorithm.branch("1.4");
		public static readonly ASN1ObjectIdentifier blake2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2");
		public static readonly ASN1ObjectIdentifier id_blake2b160 = blake2.branch("1.5");
		public static readonly ASN1ObjectIdentifier id_blake2b256 = blake2.branch("1.8");
		public static readonly ASN1ObjectIdentifier id_blake2b384 = blake2.branch("1.12");
		public static readonly ASN1ObjectIdentifier id_blake2b512 = blake2.branch("1.16");
		public static readonly ASN1ObjectIdentifier id_blake2s128 = blake2.branch("2.4");
		public static readonly ASN1ObjectIdentifier id_blake2s160 = blake2.branch("2.5");
		public static readonly ASN1ObjectIdentifier id_blake2s224 = blake2.branch("2.7");
		public static readonly ASN1ObjectIdentifier id_blake2s256 = blake2.branch("2.8");
		public static readonly ASN1ObjectIdentifier id_scrypt = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.11");
	}

}