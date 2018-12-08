namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// Object Identifiers from RFC 5272
	/// </summary>
	public interface CMCObjectIdentifiers
	{
		//   id_pkix OBJECT IDENTIFIER  ::= { iso(1) identified_organization(3)
		//       dod(6) internet(1) security(5) mechanisms(5) pkix(7) }

	   // The following controls have the type OCTET STRING

	   // The following controls have the type UTF8String

	   // The following controls have the type INTEGER

	   // The following controls have the type OCTET STRING

		// This is the content type used for a request message in the protocol

		//  This defines the response message in the protocol

		// Used to return status state in a response


		// Used for RAs to add extensions to certification requests



		//  Replaces CMC Status Info
		//


		//  Allow for distribution of trust anchors
		//

		//   These two items use BodyPartList

		// Inform follow on servers that one or more controls have already been
		// processed

		//  Identity Proof control w/ algorithm agility
	}

	public static class CMCObjectIdentifiers_Fields
	{
	   public static readonly ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
	   public static readonly ASN1ObjectIdentifier id_cmc = id_pkix.branch("7");
	   public static readonly ASN1ObjectIdentifier id_cct = id_pkix.branch("12");
	   public static readonly ASN1ObjectIdentifier id_cmc_identityProof = id_cmc.branch("3");
	   public static readonly ASN1ObjectIdentifier id_cmc_dataReturn = id_cmc.branch("4");
	   public static readonly ASN1ObjectIdentifier id_cmc_regInfo = id_cmc.branch("18");
	   public static readonly ASN1ObjectIdentifier id_cmc_responseInfo = id_cmc.branch("19");
	   public static readonly ASN1ObjectIdentifier id_cmc_queryPending = id_cmc.branch("21");
	   public static readonly ASN1ObjectIdentifier id_cmc_popLinkRandom = id_cmc.branch("22");
	   public static readonly ASN1ObjectIdentifier id_cmc_popLinkWitness = id_cmc.branch("23");
	   public static readonly ASN1ObjectIdentifier id_cmc_identification = id_cmc.branch("2");
	   public static readonly ASN1ObjectIdentifier id_cmc_transactionId = id_cmc.branch("5");
	   public static readonly ASN1ObjectIdentifier id_cmc_senderNonce = id_cmc.branch("6");
	   public static readonly ASN1ObjectIdentifier id_cmc_recipientNonce = id_cmc.branch("7");
	   public static readonly ASN1ObjectIdentifier id_cct_PKIData = id_cct.branch("2");
		public static readonly ASN1ObjectIdentifier id_cct_PKIResponse = id_cct.branch("3");
		public static readonly ASN1ObjectIdentifier id_cmc_statusInfo = id_cmc.branch("1");
		public static readonly ASN1ObjectIdentifier id_cmc_addExtensions = id_cmc.branch("8");
		public static readonly ASN1ObjectIdentifier id_cmc_encryptedPOP = id_cmc.branch("9");
		public static readonly ASN1ObjectIdentifier id_cmc_decryptedPOP = id_cmc.branch("10");
		public static readonly ASN1ObjectIdentifier id_cmc_lraPOPWitness = id_cmc.branch("11");
		public static readonly ASN1ObjectIdentifier id_cmc_getCert = id_cmc.branch("15");
		public static readonly ASN1ObjectIdentifier id_cmc_getCRL = id_cmc.branch("16");
		public static readonly ASN1ObjectIdentifier id_cmc_revokeRequest = id_cmc.branch("17");
		public static readonly ASN1ObjectIdentifier id_cmc_confirmCertAcceptance = id_cmc.branch("24");
		public static readonly ASN1ObjectIdentifier id_cmc_statusInfoV2 = id_cmc.branch("25");
		public static readonly ASN1ObjectIdentifier id_cmc_trustedAnchors = id_cmc.branch("26");
		public static readonly ASN1ObjectIdentifier id_cmc_authData = id_cmc.branch("27");
		public static readonly ASN1ObjectIdentifier id_cmc_batchRequests = id_cmc.branch("28");
		public static readonly ASN1ObjectIdentifier id_cmc_batchResponses = id_cmc.branch("29");
		public static readonly ASN1ObjectIdentifier id_cmc_publishCert = id_cmc.branch("30");
		public static readonly ASN1ObjectIdentifier id_cmc_modCertTemplate = id_cmc.branch("31");
		public static readonly ASN1ObjectIdentifier id_cmc_controlProcessed = id_cmc.branch("32");
		public static readonly ASN1ObjectIdentifier id_cmc_identityProofV2 = id_cmc.branch("34");
		public static readonly ASN1ObjectIdentifier id_cmc_popLinkWitnessV2 = id_cmc.branch("33");
	}

}