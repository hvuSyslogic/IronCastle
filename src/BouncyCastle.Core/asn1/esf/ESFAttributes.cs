using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.esf
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

	public interface ESFAttributes
	{
	}

	public static class ESFAttributes_Fields
	{
		public static readonly ASN1ObjectIdentifier sigPolicyId = PKCSObjectIdentifiers_Fields.id_aa_ets_sigPolicyId;
		public static readonly ASN1ObjectIdentifier commitmentType = PKCSObjectIdentifiers_Fields.id_aa_ets_commitmentType;
		public static readonly ASN1ObjectIdentifier signerLocation = PKCSObjectIdentifiers_Fields.id_aa_ets_signerLocation;
		public static readonly ASN1ObjectIdentifier signerAttr = PKCSObjectIdentifiers_Fields.id_aa_ets_signerAttr;
		public static readonly ASN1ObjectIdentifier otherSigCert = PKCSObjectIdentifiers_Fields.id_aa_ets_otherSigCert;
		public static readonly ASN1ObjectIdentifier contentTimestamp = PKCSObjectIdentifiers_Fields.id_aa_ets_contentTimestamp;
		public static readonly ASN1ObjectIdentifier certificateRefs = PKCSObjectIdentifiers_Fields.id_aa_ets_certificateRefs;
		public static readonly ASN1ObjectIdentifier revocationRefs = PKCSObjectIdentifiers_Fields.id_aa_ets_revocationRefs;
		public static readonly ASN1ObjectIdentifier certValues = PKCSObjectIdentifiers_Fields.id_aa_ets_certValues;
		public static readonly ASN1ObjectIdentifier revocationValues = PKCSObjectIdentifiers_Fields.id_aa_ets_revocationValues;
		public static readonly ASN1ObjectIdentifier escTimeStamp = PKCSObjectIdentifiers_Fields.id_aa_ets_escTimeStamp;
		public static readonly ASN1ObjectIdentifier certCRLTimestamp = PKCSObjectIdentifiers_Fields.id_aa_ets_certCRLTimestamp;
		public static readonly ASN1ObjectIdentifier archiveTimestamp = PKCSObjectIdentifiers_Fields.id_aa_ets_archiveTimestamp;
		public static readonly ASN1ObjectIdentifier archiveTimestampV2 = PKCSObjectIdentifiers_Fields.id_aa.branch("48");
	}

}