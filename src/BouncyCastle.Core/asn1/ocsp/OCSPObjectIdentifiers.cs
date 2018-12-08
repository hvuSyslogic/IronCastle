namespace org.bouncycastle.asn1.ocsp
{

	/// <summary>
	/// OIDs for <a href="http://tools.ietf.org/html/rfc2560">RFC 2560</a> and <a href="http://tools.ietf.org/html/rfc6960">RFC 6960</a>
	/// Online Certificate Status Protocol - OCSP.
	/// </summary>
	public interface OCSPObjectIdentifiers
	{
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1 </summary>
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.1 </summary>

		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.2 </summary>
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.3 </summary>

		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.4 </summary>
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.5 </summary>
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.6 </summary>
		/// <summary>
		/// OID: 1.3.6.1.5.5.7.48.1.7 </summary>

	}

	public static class OCSPObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_basic = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_nonce = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_crl = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.3");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_response = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.4");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_nocheck = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.6");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_service_locator = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.7");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_pref_sig_algs = id_pkix_ocsp.branch("8");
		public static readonly ASN1ObjectIdentifier id_pkix_ocsp_extended_revoke = id_pkix_ocsp.branch("9");
	}

}