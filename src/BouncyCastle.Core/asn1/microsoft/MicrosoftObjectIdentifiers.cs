namespace org.bouncycastle.asn1.microsoft
{

	/// <summary>
	/// Microsoft
	/// <para>
	/// Object identifier base:
	/// <pre>
	///    iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) microsoft(311)
	/// </pre>
	/// 1.3.6.1.4.1.311
	/// </para>
	/// </summary>
	public interface MicrosoftObjectIdentifiers
	{
		/// <summary>
		/// Base OID: 1.3.6.1.4.1.311 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.20.2 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.21.1 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.21.2 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.21.4 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.21.7 </summary>
		/// <summary>
		/// OID: 1.3.6.1.4.1.311.21.10 </summary>
	}

	public static class MicrosoftObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier microsoft = new ASN1ObjectIdentifier("1.3.6.1.4.1.311");
		public static readonly ASN1ObjectIdentifier microsoftCertTemplateV1 = microsoft.branch("20.2");
		public static readonly ASN1ObjectIdentifier microsoftCaVersion = microsoft.branch("21.1");
		public static readonly ASN1ObjectIdentifier microsoftPrevCaCertHash = microsoft.branch("21.2");
		public static readonly ASN1ObjectIdentifier microsoftCrlNextPublish = microsoft.branch("21.4");
		public static readonly ASN1ObjectIdentifier microsoftCertTemplateV2 = microsoft.branch("21.7");
		public static readonly ASN1ObjectIdentifier microsoftAppPolicies = microsoft.branch("21.10");
	}

}