using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using NHKeyFactorySpi = org.bouncycastle.pqc.jcajce.provider.newhope.NHKeyFactorySpi;

	public class NH
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".newhope.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.NH", PREFIX + "NHKeyFactorySpi");
				provider.addAlgorithm("KeyPairGenerator.NH", PREFIX + "NHKeyPairGeneratorSpi");

				provider.addAlgorithm("KeyAgreement.NH", PREFIX + "KeyAgreementSpi");

				AsymmetricKeyInfoConverter keyFact = new NHKeyFactorySpi();

				registerOid(provider, PQCObjectIdentifiers_Fields.newHope, "NH", keyFact);
			}
		}
	}

}