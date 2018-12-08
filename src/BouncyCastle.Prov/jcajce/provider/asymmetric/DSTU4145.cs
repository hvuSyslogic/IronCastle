using org.bouncycastle.asn1.ua;

namespace org.bouncycastle.jcajce.provider.asymmetric
{
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.dstu.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class DSTU4145
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dstu.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.DSTU4145", PREFIX + "KeyFactorySpi");
				provider.addAlgorithm("Alg.Alias.KeyFactory.DSTU-4145-2002", "DSTU4145");
				provider.addAlgorithm("Alg.Alias.KeyFactory.DSTU4145-3410", "DSTU4145");

				registerOid(provider, UAObjectIdentifiers_Fields.dstu4145le, "DSTU4145", new KeyFactorySpi());
				registerOidAlgorithmParameters(provider, UAObjectIdentifiers_Fields.dstu4145le, "DSTU4145");
				registerOid(provider, UAObjectIdentifiers_Fields.dstu4145be, "DSTU4145", new KeyFactorySpi());
				registerOidAlgorithmParameters(provider, UAObjectIdentifiers_Fields.dstu4145be, "DSTU4145");

				provider.addAlgorithm("KeyPairGenerator.DSTU4145", PREFIX + "KeyPairGeneratorSpi");
				provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DSTU-4145", "DSTU4145");
				provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DSTU-4145-2002", "DSTU4145");

				provider.addAlgorithm("Signature.DSTU4145", PREFIX + "SignatureSpi");
				provider.addAlgorithm("Alg.Alias.Signature.DSTU-4145", "DSTU4145");
				provider.addAlgorithm("Alg.Alias.Signature.DSTU-4145-2002", "DSTU4145");

				addSignatureAlgorithm(provider, "GOST3411", "DSTU4145LE", PREFIX + "SignatureSpiLe", UAObjectIdentifiers_Fields.dstu4145le);
				addSignatureAlgorithm(provider, "GOST3411", "DSTU4145", PREFIX + "SignatureSpi", UAObjectIdentifiers_Fields.dstu4145be);
			}
		}
	}

}