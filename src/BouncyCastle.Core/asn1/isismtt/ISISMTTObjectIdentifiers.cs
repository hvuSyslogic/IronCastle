namespace org.bouncycastle.asn1.isismtt
{

	/// <summary>
	/// ISISMT -- Industrial Signature Interoperability Specification
	/// </summary>
	public interface ISISMTTObjectIdentifiers
	{

		/// <summary>
		/// 1.3.36.8 </summary>

		/// <summary>
		/// 1.3.36.8.1 </summary>

		/// <summary>
		/// The id-isismtt-cp-accredited OID indicates that the certificate is a
		/// qualified certificate according to Directive 1999/93/EC of the European
		/// Parliament and of the Council of 13 December 1999 on a Community
		/// Framework for Electronic Signatures, which additionally conforms the
		/// special requirements of the SigG and has been issued by an accredited CA.
		/// <para>
		/// 1.3.36.8.1.1
		/// </para>
		/// </summary>

		/// <summary>
		/// 1.3.36.8.3 </summary>

		/// <summary>
		/// Certificate extensionDate of certificate generation
		/// <pre>
		///     DateOfCertGenSyntax ::= GeneralizedTime
		/// </pre>
		/// OID: 1.3.36.8.3.1
		/// </summary>

		/// <summary>
		/// Attribute to indicate that the certificate holder may sign in the name of
		/// a third person. May also be used as extension in a certificate.
		/// <para>
		/// OID: 1.3.36.8.3.2
		/// </para>
		/// </summary>

		/// <summary>
		/// Attribute to indicate admissions to certain professions. May be used as
		/// attribute in attribute certificate or as extension in a certificate
		/// <para>
		/// OID: 1.3.36.8.3.3
		/// </para>
		/// </summary>

		/// <summary>
		/// Monetary limit for transactions. The QcEuMonetaryLimit QC statement MUST
		/// be used in new certificates in place of the extension/attribute
		/// MonetaryLimit since January 1, 2004. For the sake of backward
		/// compatibility with certificates already in use, SigG conforming
		/// components MUST support MonetaryLimit (as well as QcEuLimitValue).
		/// <para>
		/// OID: 1.3.36.8.3.4
		/// </para>
		/// </summary>

		/// <summary>
		/// A declaration of majority. May be used as attribute in attribute
		/// certificate or as extension in a certificate
		/// <para>
		/// OID: 1.3.36.8.3.5
		/// </para>
		/// </summary>

		/// <summary>
		/// Serial number of the smart card containing the corresponding private key
		/// <pre>
		///    ICCSNSyntax ::= OCTET STRING (SIZE(8..20))
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.6
		/// </para>
		/// </summary>

		/// <summary>
		/// Reference for a file of a smartcard that stores the public key of this
		/// certificate and that is used as "security anchor".
		/// <pre>
		///    PKReferenceSyntax ::= OCTET STRING (SIZE(20))
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.7
		/// </para>
		/// </summary>

		/// <summary>
		/// Some other restriction regarding the usage of this certificate. May be
		/// used as attribute in attribute certificate or as extension in a
		/// certificate.
		/// <pre>
		///    RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.8
		/// 
		/// </para>
		/// </summary>
		/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.Restriction </seealso>

		/// <summary>
		/// (Single)Request extension: Clients may include this extension in a
		/// (single) Request to request the responder to send the certificate in the
		/// response message along with the status information. Besides the LDAP
		/// service, this extension provides another mechanism for the distribution
		/// of certificates, which MAY optionally be provided by certificate
		/// repositories.
		/// <pre>
		///    RetrieveIfAllowed ::= BOOLEAN
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.9
		/// </para>
		/// </summary>

		/// <summary>
		/// SingleOCSPResponse extension: The certificate requested by the client by
		/// inserting the RetrieveIfAllowed extension in the request, will be
		/// returned in this extension.
		/// <para>
		/// OID: 1.3.36.8.3.10
		/// 
		/// </para>
		/// </summary>
		/// <seealso cref= org.bouncycastle.asn1.isismtt.ocsp.RequestedCertificate </seealso>

		/// <summary>
		/// Base ObjectIdentifier for naming authorities
		/// <para>
		/// OID: 1.3.36.8.3.11
		/// </para>
		/// </summary>

		/// <summary>
		/// SingleOCSPResponse extension: Date, when certificate has been published
		/// in the directory and status information has become available. Currently,
		/// accrediting authorities enforce that SigG-conforming OCSP servers include
		/// this extension in the responses.
		/// 
		/// <pre>
		///    CertInDirSince ::= GeneralizedTime
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.12
		/// </para>
		/// </summary>

		/// <summary>
		/// Hash of a certificate in OCSP.
		/// <para>
		/// OID: 1.3.36.8.3.13
		/// 
		/// </para>
		/// </summary>
		/// <seealso cref= org.bouncycastle.asn1.isismtt.ocsp.CertHash </seealso>

		/// <summary>
		/// <pre>
		///    NameAtBirth ::= DirectoryString(SIZE(1..64)
		/// </pre>
		/// 
		/// Used in
		/// <seealso cref="org.bouncycastle.asn1.x509.SubjectDirectoryAttributes SubjectDirectoryAttributes"/>
		/// <para>
		/// OID: 1.3.36.8.3.14
		/// </para>
		/// </summary>

		/// <summary>
		/// Some other information of non-restrictive nature regarding the usage of
		/// this certificate. May be used as attribute in atribute certificate or as
		/// extension in a certificate.
		/// 
		/// <pre>
		///    AdditionalInformationSyntax ::= DirectoryString (SIZE(1..2048))
		/// </pre>
		/// <para>
		/// OID: 1.3.36.8.3.15
		/// 
		/// </para>
		/// </summary>
		/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.AdditionalInformationSyntax </seealso>

		/// <summary>
		/// Indicates that an attribute certificate exists, which limits the
		/// usability of this public key certificate. Whenever verifying a signature
		/// with the help of this certificate, the content of the corresponding
		/// attribute certificate should be concerned. This extension MUST be
		/// included in a PKC, if a corresponding attribute certificate (having the
		/// PKC as base certificate) contains some attribute that restricts the
		/// usability of the PKC too. Attribute certificates with restricting content
		/// MUST always be included in the signed document.
		/// <pre>
		///    LiabilityLimitationFlagSyntax ::= BOOLEAN
		/// </pre>
		/// <para>
		/// OID: 0.2.262.1.10.12.0
		/// </para>
		/// </summary>
	}

	public static class ISISMTTObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_isismtt = new ASN1ObjectIdentifier("1.3.36.8");
		public static readonly ASN1ObjectIdentifier id_isismtt_cp = id_isismtt.branch("1");
		public static readonly ASN1ObjectIdentifier id_isismtt_cp_accredited = id_isismtt_cp.branch("1");
		public static readonly ASN1ObjectIdentifier id_isismtt_at = id_isismtt.branch("3");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_dateOfCertGen = id_isismtt_at.branch("1");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_procuration = id_isismtt_at.branch("2");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_admission = id_isismtt_at.branch("3");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_monetaryLimit = id_isismtt_at.branch("4");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_declarationOfMajority = id_isismtt_at.branch("5");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_iCCSN = id_isismtt_at.branch("6");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_PKReference = id_isismtt_at.branch("7");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_restriction = id_isismtt_at.branch("8");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_retrieveIfAllowed = id_isismtt_at.branch("9");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_requestedCertificate = id_isismtt_at.branch("10");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_namingAuthorities = id_isismtt_at.branch("11");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_certInDirSince = id_isismtt_at.branch("12");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_certHash = id_isismtt_at.branch("13");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_nameAtBirth = id_isismtt_at.branch("14");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_additionalInformation = id_isismtt_at.branch("15");
		public static readonly ASN1ObjectIdentifier id_isismtt_at_liabilityLimitationFlag = new ASN1ObjectIdentifier("0.2.262.1.10.12.0");
	}

}