using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.smime
{
	
	public interface SMIMEAttributes
	{
	}

	public static class SMIMEAttributes_Fields
	{
		public static readonly ASN1ObjectIdentifier smimeCapabilities = PKCSObjectIdentifiers_Fields.pkcs_9_at_smimeCapabilities;
		public static readonly ASN1ObjectIdentifier encrypKeyPref = PKCSObjectIdentifiers_Fields.id_aa_encrypKeyPref;
	}

}