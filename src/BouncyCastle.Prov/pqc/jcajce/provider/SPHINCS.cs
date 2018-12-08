using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using Sphincs256KeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;

	public class SPHINCS
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".sphincs.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.SPHINCS256", PREFIX + "Sphincs256KeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.SPHINCS256", PREFIX + "Sphincs256KeyPairGeneratorSpi");

				addSignatureAlgorithm(provider, "SHA512", "SPHINCS256", PREFIX + "SignatureSpi$withSha512", PQCObjectIdentifiers_Fields.sphincs256_with_SHA512);
				addSignatureAlgorithm(provider, "SHA3-512", "SPHINCS256", PREFIX + "SignatureSpi$withSha3_512", PQCObjectIdentifiers_Fields.sphincs256_with_SHA3_512);

				AsymmetricKeyInfoConverter keyFact = new Sphincs256KeyFactorySpi();

				registerOid(provider, PQCObjectIdentifiers_Fields.sphincs256, "SPHINCS256", keyFact);
				registerOidAlgorithmParameters(provider, PQCObjectIdentifiers_Fields.sphincs256, "SPHINCS256");
			}
		}
	}

}