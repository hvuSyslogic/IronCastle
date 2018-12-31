using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.crmf
{
	
	public interface CRMFObjectIdentifiers
	{
		/// <summary>
		/// 1.3.6.1.5.5.7 </summary>

		// arc for Internet X.509 PKI protocols and their components

		/// <summary>
		/// 1.3.6.1.5.5.7.5 </summary>

		/// <summary>
		/// 1.3.6.1.5.5.7.1 </summary>
		/// <summary>
		/// 1.3.6.1.5.5.7.1.1 </summary>
		/// <summary>
		/// 1.3.6.1.5.5.7.1.2 </summary>
		/// <summary>
		/// 1.3.6.1.5.5.7.1.3 </summary>
		/// <summary>
		/// 1.3.6.1.5.5.7.1.4 </summary>

		/// <summary>
		/// 1.2.840.113549.1.9.16.1,21 </summary>

		/// <summary>
		/// 1.3.6.1.5.5.7.6 </summary>
	}

	public static class CRMFObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
		public static readonly ASN1ObjectIdentifier id_pkip = id_pkix.branch("5");
		public static readonly ASN1ObjectIdentifier id_regCtrl = id_pkip.branch("1");
		public static readonly ASN1ObjectIdentifier id_regCtrl_regToken = id_regCtrl.branch("1");
		public static readonly ASN1ObjectIdentifier id_regCtrl_authenticator = id_regCtrl.branch("2");
		public static readonly ASN1ObjectIdentifier id_regCtrl_pkiPublicationInfo = id_regCtrl.branch("3");
		public static readonly ASN1ObjectIdentifier id_regCtrl_pkiArchiveOptions = id_regCtrl.branch("4");
		public static readonly ASN1ObjectIdentifier id_ct_encKeyWithID = PKCSObjectIdentifiers_Fields.id_ct.branch("21");
		public static readonly ASN1ObjectIdentifier id_alg = id_pkix.branch("6");
		public static readonly ASN1ObjectIdentifier id_dh_sig_hmac_sha1 = id_alg.branch("3");
		public static readonly ASN1ObjectIdentifier id_alg_dh_pop = id_alg.branch("4");
	}

}