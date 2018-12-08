using org.bouncycastle.asn1.eac;

namespace org.bouncycastle.eac.@operator.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;

	public abstract class EACHelper
	{
		private static readonly Hashtable sigNames = new Hashtable();

		static EACHelper()
		{
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_1, "SHA1withRSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_256, "SHA256withRSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_1, "SHA1withRSAandMGF1");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_256, "SHA256withRSAandMGF1");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_512, "SHA512withRSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_512, "SHA512withRSAandMGF1");

			sigNames.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1, "SHA1withECDSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224, "SHA224withECDSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256, "SHA256withECDSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384, "SHA384withECDSA");
			sigNames.put(EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512, "SHA512withECDSA");
		}

		public virtual Signature getSignature(ASN1ObjectIdentifier oid)
		{
			return createSignature((string)sigNames.get(oid));
		}

		public abstract Signature createSignature(string type);
	}

}