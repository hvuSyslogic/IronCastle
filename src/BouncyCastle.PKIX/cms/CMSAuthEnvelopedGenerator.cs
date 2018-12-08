using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.cms
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

	public class CMSAuthEnvelopedGenerator
	{
		public static readonly string AES128_CCM = NISTObjectIdentifiers_Fields.id_aes128_CCM.getId();
		public static readonly string AES192_CCM = NISTObjectIdentifiers_Fields.id_aes192_CCM.getId();
		public static readonly string AES256_CCM = NISTObjectIdentifiers_Fields.id_aes256_CCM.getId();
		public static readonly string AES128_GCM = NISTObjectIdentifiers_Fields.id_aes128_GCM.getId();
		public static readonly string AES192_GCM = NISTObjectIdentifiers_Fields.id_aes192_GCM.getId();
		public static readonly string AES256_GCM = NISTObjectIdentifiers_Fields.id_aes256_GCM.getId();
	}

}