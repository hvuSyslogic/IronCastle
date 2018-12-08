using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.esf
{
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

	public interface CommitmentTypeIdentifier
	{
	}

	public static class CommitmentTypeIdentifier_Fields
	{
		public static readonly ASN1ObjectIdentifier proofOfOrigin = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfOrigin;
		public static readonly ASN1ObjectIdentifier proofOfReceipt = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfReceipt;
		public static readonly ASN1ObjectIdentifier proofOfDelivery = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfDelivery;
		public static readonly ASN1ObjectIdentifier proofOfSender = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfSender;
		public static readonly ASN1ObjectIdentifier proofOfApproval = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfApproval;
		public static readonly ASN1ObjectIdentifier proofOfCreation = PKCSObjectIdentifiers_Fields.id_cti_ets_proofOfCreation;
	}

}