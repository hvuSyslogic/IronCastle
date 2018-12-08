using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using RainbowKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;

	public class Rainbow
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".rainbow.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.Rainbow", PREFIX + "RainbowKeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.Rainbow", PREFIX + "RainbowKeyPairGeneratorSpi");

				addSignatureAlgorithm(provider, "SHA224", "Rainbow", PREFIX + "SignatureSpi$withSha224", PQCObjectIdentifiers_Fields.rainbowWithSha224);
				addSignatureAlgorithm(provider, "SHA256", "Rainbow", PREFIX + "SignatureSpi$withSha256", PQCObjectIdentifiers_Fields.rainbowWithSha256);
				addSignatureAlgorithm(provider, "SHA384", "Rainbow", PREFIX + "SignatureSpi$withSha384", PQCObjectIdentifiers_Fields.rainbowWithSha384);
				addSignatureAlgorithm(provider, "SHA512", "Rainbow", PREFIX + "SignatureSpi$withSha512", PQCObjectIdentifiers_Fields.rainbowWithSha512);

				AsymmetricKeyInfoConverter keyFact = new RainbowKeyFactorySpi();

				registerOid(provider, PQCObjectIdentifiers_Fields.rainbow, "Rainbow", keyFact);
			}
		}
	}

}