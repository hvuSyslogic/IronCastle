using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.cms
{

	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

	/// <summary>
	/// General class for generating a CMS enveloped-data message.
	/// </summary>
	public class CMSEnvelopedGenerator
	{
		public static readonly string DES_EDE3_CBC = PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId();
		public static readonly string RC2_CBC = PKCSObjectIdentifiers_Fields.RC2_CBC.getId();
		public const string IDEA_CBC = "1.3.6.1.4.1.188.7.1.1.2";
		public const string CAST5_CBC = "1.2.840.113533.7.66.10";
		public static readonly string AES128_CBC = NISTObjectIdentifiers_Fields.id_aes128_CBC.getId();
		public static readonly string AES192_CBC = NISTObjectIdentifiers_Fields.id_aes192_CBC.getId();
		public static readonly string AES256_CBC = NISTObjectIdentifiers_Fields.id_aes256_CBC.getId();
		public static readonly string CAMELLIA128_CBC = NTTObjectIdentifiers_Fields.id_camellia128_cbc.getId();
		public static readonly string CAMELLIA192_CBC = NTTObjectIdentifiers_Fields.id_camellia192_cbc.getId();
		public static readonly string CAMELLIA256_CBC = NTTObjectIdentifiers_Fields.id_camellia256_cbc.getId();
		public static readonly string SEED_CBC = KISAObjectIdentifiers_Fields.id_seedCBC.getId();

		public static readonly string DES_EDE3_WRAP = PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId();
		public static readonly string AES128_WRAP = NISTObjectIdentifiers_Fields.id_aes128_wrap.getId();
		public static readonly string AES192_WRAP = NISTObjectIdentifiers_Fields.id_aes192_wrap.getId();
		public static readonly string AES256_WRAP = NISTObjectIdentifiers_Fields.id_aes256_wrap.getId();
		public static readonly string CAMELLIA128_WRAP = NTTObjectIdentifiers_Fields.id_camellia128_wrap.getId();
		public static readonly string CAMELLIA192_WRAP = NTTObjectIdentifiers_Fields.id_camellia192_wrap.getId();
		public static readonly string CAMELLIA256_WRAP = NTTObjectIdentifiers_Fields.id_camellia256_wrap.getId();
		public static readonly string SEED_WRAP = KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap.getId();

		public static readonly string ECDH_SHA1KDF = X9ObjectIdentifiers_Fields.dhSinglePass_stdDH_sha1kdf_scheme.getId();
		public static readonly string ECMQV_SHA1KDF = X9ObjectIdentifiers_Fields.mqvSinglePass_sha1kdf_scheme.getId();

		internal readonly List oldRecipientInfoGenerators = new ArrayList();
		internal readonly List recipientInfoGenerators = new ArrayList();

		protected internal CMSAttributeTableGenerator unprotectedAttributeGenerator = null;

		protected internal OriginatorInfo originatorInfo;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSEnvelopedGenerator()
		{
		}

		public virtual void setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
		{
			this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
		}

		public virtual void setOriginatorInfo(OriginatorInformation originatorInfo)
		{
			this.originatorInfo = originatorInfo.toASN1Structure();
		}

		/// <summary>
		/// Add a generator to produce the recipient info required.
		/// </summary>
		/// <param name="recipientGenerator"> a generator of a recipient info object. </param>
		public virtual void addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
		{
			recipientInfoGenerators.add(recipientGenerator);
		}
	}

}