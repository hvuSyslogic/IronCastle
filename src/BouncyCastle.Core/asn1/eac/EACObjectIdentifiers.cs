namespace org.bouncycastle.asn1.eac
{

	/// <summary>
	/// German Federal Office for Information Security
	/// (Bundesamt f&uuml;r Sicherheit in der Informationstechnik)
	/// <a href="http://www.bsi.bund.de/">http://www.bsi.bund.de/</a>
	/// <para>
	/// <a href="https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html">BSI TR-03110</a>
	/// Technical Guideline Advanced Security Mechanisms for Machine Readable Travel Documents
	/// </para>
	/// <para>
	/// <a href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03110/TR-03110_v2.1_P3pdf.pdf">
	/// Technical Guideline TR-03110-3</a>
	/// Advanced Security Mechanisms for Machine Readable Travel Documents;
	/// Part 3: Common Specifications.
	/// </para>
	/// </summary>
	public interface EACObjectIdentifiers
	{
		/// <summary>
		/// <pre>
		/// bsi-de OBJECT IDENTIFIER ::= {
		///     itu-t(0) identified-organization(4) etsi(0)
		///     reserved(127) etsi-identified-organization(0) 7
		/// }
		/// </pre>
		/// OID: 0.4.0.127.0.7
		/// </summary>

		/// <summary>
		/// <pre>
		/// id-PK OBJECT IDENTIFIER ::= {
		///     bsi-de protocols(2) smartcard(2) 1
		/// }
		/// </pre>
		/// OID: 0.4.0.127.0.7.2.2.1
		/// </summary>

		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.1.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.1.2 </summary>

		/// <summary>
		/// <pre>
		/// id-CA OBJECT IDENTIFIER ::= {
		///     bsi-de protocols(2) smartcard(2) 3
		/// }
		/// </pre>
		/// OID: 0.4.0.127.0.7.2.2.3
		/// </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.3.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.3.1.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.3.2 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.3.2.1 </summary>

		/// <summary>
		/// <pre>
		/// id-TA OBJECT IDENTIFIER ::= {
		///     bsi-de protocols(2) smartcard(2) 2
		/// }
		/// </pre>
		/// OID: 0.4.0.127.0.7.2.2.2
		/// </summary>

		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.2 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.3 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.4 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.5 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.1.6 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2.1 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2.2 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2.3 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2.4 </summary>
		/// <summary>
		/// OID: 0.4.0.127.0.7.2.2.2.2.5 </summary>

		/// <summary>
		/// <pre>
		/// id-EAC-ePassport OBJECT IDENTIFIER ::= {
		///     bsi-de applications(3) mrtd(1) roles(2) 1
		/// }
		/// </pre>
		/// OID: 0.4.0.127.0.7.3.1.2.1
		/// </summary>
	}

	public static class EACObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier bsi_de = new ASN1ObjectIdentifier("0.4.0.127.0.7");
		public static readonly ASN1ObjectIdentifier id_PK = bsi_de.branch("2.2.1");
		public static readonly ASN1ObjectIdentifier id_PK_DH = id_PK.branch("1");
		public static readonly ASN1ObjectIdentifier id_PK_ECDH = id_PK.branch("2");
		public static readonly ASN1ObjectIdentifier id_CA = bsi_de.branch("2.2.3");
		public static readonly ASN1ObjectIdentifier id_CA_DH = id_CA.branch("1");
		public static readonly ASN1ObjectIdentifier id_CA_DH_3DES_CBC_CBC = id_CA_DH.branch("1");
		public static readonly ASN1ObjectIdentifier id_CA_ECDH = id_CA.branch("2");
		public static readonly ASN1ObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = id_CA_ECDH.branch("1");
		public static readonly ASN1ObjectIdentifier id_TA = bsi_de.branch("2.2.2");
		public static readonly ASN1ObjectIdentifier id_TA_RSA = id_TA.branch("1");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_1 = id_TA_RSA.branch("1");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_256 = id_TA_RSA.branch("2");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_1 = id_TA_RSA.branch("3");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_256 = id_TA_RSA.branch("4");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_512 = id_TA_RSA.branch("5");
		public static readonly ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_512 = id_TA_RSA.branch("6");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA = id_TA.branch("2");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA_SHA_1 = id_TA_ECDSA.branch("1");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA_SHA_224 = id_TA_ECDSA.branch("2");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA_SHA_256 = id_TA_ECDSA.branch("3");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA_SHA_384 = id_TA_ECDSA.branch("4");
		public static readonly ASN1ObjectIdentifier id_TA_ECDSA_SHA_512 = id_TA_ECDSA.branch("5");
		public static readonly ASN1ObjectIdentifier id_EAC_ePassport = bsi_de.branch("3.1.2.1");
	}

}