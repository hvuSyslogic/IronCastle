namespace org.bouncycastle.asn1.dvcs
{

	/// <summary>
	/// OIDs for <a href="http://tools.ietf.org/html/rfc3029">RFC 3029</a>
	/// Data Validation and Certification Server Protocols
	/// </summary>
	public interface DVCSObjectIdentifiers
	{
		/// <summary>
		/// Base OID id-pkix: 1.3.6.1.5.5.7 </summary>
		/// <summary>
		/// Base OID id-smime: 1.2.840.113549.1.9.16 </summary>

		/// <summary>
		/// Authority Information Access for DVCS; id-ad-dcvs;  OID: 1.3.6.1.5.5.7.48.4 </summary>

		/// <summary>
		/// Key Purpose for DVCS; id-kp-dvcs; OID: 1.3.6.1.5.5.7.3.10 </summary>

		/// <summary>
		/// SMIME eContentType id-ct-DVCSRequestData;   OID: 1.2.840.113549.1.9.16.1.7 </summary>
		/// <summary>
		/// SMIME eContentType id-ct-DVCSResponseData;  OID: 1.2.840.113549.1.9.16.1.8 </summary>

		/// <summary>
		/// SMIME DataValidation certificate attribute id-aa-dvcs-dvc;  OID: 1.2.840.113549.1.9.16.2,29 </summary>
	}

	public static class DVCSObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
		public static readonly ASN1ObjectIdentifier id_smime = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16");
		public static readonly ASN1ObjectIdentifier id_ad_dvcs = id_pkix.branch("48.4");
		public static readonly ASN1ObjectIdentifier id_kp_dvcs = id_pkix.branch("3.10");
		public static readonly ASN1ObjectIdentifier id_ct_DVCSRequestData = id_smime.branch("1.7");
		public static readonly ASN1ObjectIdentifier id_ct_DVCSResponseData = id_smime.branch("1.8");
		public static readonly ASN1ObjectIdentifier id_aa_dvcs_dvc = id_smime.branch("2.29");
	}

}