using org.bouncycastle.asn1.bc;
using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using XMSSKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
	using XMSSMTKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;

	public class XMSS
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".xmss.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.XMSS", PREFIX + "XMSSKeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.XMSS", PREFIX + "XMSSKeyPairGeneratorSpi");

				addSignatureAlgorithm(provider, "XMSS-SHA256", PREFIX + "XMSSSignatureSpi$withSha256", BCObjectIdentifiers_Fields.xmss_SHA256);
				addSignatureAlgorithm(provider, "XMSS-SHAKE128", PREFIX + "XMSSSignatureSpi$withShake128", BCObjectIdentifiers_Fields.xmss_SHAKE128);
				addSignatureAlgorithm(provider, "XMSS-SHA512", PREFIX + "XMSSSignatureSpi$withSha512", BCObjectIdentifiers_Fields.xmss_SHA512);
				addSignatureAlgorithm(provider, "XMSS-SHAKE256", PREFIX + "XMSSSignatureSpi$withShake256", BCObjectIdentifiers_Fields.xmss_SHAKE256);

				addSignatureAlgorithm(provider, "SHA256", "XMSS-SHA256", PREFIX + "XMSSSignatureSpi$withSha256andPrehash", BCObjectIdentifiers_Fields.xmss_SHA256ph);
				addSignatureAlgorithm(provider, "SHAKE128", "XMSS-SHAKE128", PREFIX + "XMSSSignatureSpi$withShake128andPrehash", BCObjectIdentifiers_Fields.xmss_SHAKE128ph);
				addSignatureAlgorithm(provider, "SHA512", "XMSS-SHA512", PREFIX + "XMSSSignatureSpi$withSha512andPrehash", BCObjectIdentifiers_Fields.xmss_SHA512ph);
				addSignatureAlgorithm(provider, "SHAKE256", "XMSS-SHAKE256", PREFIX + "XMSSSignatureSpi$withShake256andPrehash", BCObjectIdentifiers_Fields.xmss_SHAKE256ph);
				provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSS", "SHA256WITHXMSS-SHA256");
				provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSS", "SHAKE128WITHXMSS-SHAKE128");
				provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSS", "SHA512WITHXMSS-SHA512");
				provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSS", "SHAKE256WITHXMSS-SHAKE256");

				provider.addAlgorithm("KeyFactory.XMSSMT", PREFIX + "XMSSMTKeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.XMSSMT", PREFIX + "XMSSMTKeyPairGeneratorSpi");

				addSignatureAlgorithm(provider, "XMSSMT-SHA256", PREFIX + "XMSSMTSignatureSpi$withSha256", BCObjectIdentifiers_Fields.xmss_mt_SHA256);
				addSignatureAlgorithm(provider, "XMSSMT-SHAKE128", PREFIX + "XMSSMTSignatureSpi$withShake128", BCObjectIdentifiers_Fields.xmss_mt_SHAKE128);
				addSignatureAlgorithm(provider, "XMSSMT-SHA512", PREFIX + "XMSSMTSignatureSpi$withSha512", BCObjectIdentifiers_Fields.xmss_mt_SHA512);
				addSignatureAlgorithm(provider, "XMSSMT-SHAKE256", PREFIX + "XMSSMTSignatureSpi$withShake256", BCObjectIdentifiers_Fields.xmss_mt_SHAKE256);

				addSignatureAlgorithm(provider, "SHA256", "XMSSMT-SHA256", PREFIX + "XMSSMTSignatureSpi$withSha256andPrehash", BCObjectIdentifiers_Fields.xmss_mt_SHA256ph);
				addSignatureAlgorithm(provider, "SHAKE128", "XMSSMT-SHAKE128", PREFIX + "XMSSMTSignatureSpi$withShake128andPrehash", BCObjectIdentifiers_Fields.xmss_mt_SHAKE128ph);
				addSignatureAlgorithm(provider, "SHA512", "XMSSMT-SHA512", PREFIX + "XMSSMTSignatureSpi$withSha512andPrehash", BCObjectIdentifiers_Fields.xmss_mt_SHA512ph);
				addSignatureAlgorithm(provider, "SHAKE256", "XMSSMT-SHAKE256", PREFIX + "XMSSMTSignatureSpi$withShake256andPrehash", BCObjectIdentifiers_Fields.xmss_mt_SHAKE256ph);
				provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSSMT", "SHA256WITHXMSSMT-SHA256");
				provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSSMT", "SHAKE128WITHXMSSMT-SHAKE128");
				provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSSMT", "SHA512WITHXMSSMT-SHA512");
				provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSSMT", "SHAKE256WITHXMSSMT-SHAKE256");

				registerOid(provider, PQCObjectIdentifiers_Fields.xmss, "XMSS", new XMSSKeyFactorySpi());
				registerOid(provider, PQCObjectIdentifiers_Fields.xmss_mt, "XMSSMT", new XMSSMTKeyFactorySpi());
			}
		}
	}

}