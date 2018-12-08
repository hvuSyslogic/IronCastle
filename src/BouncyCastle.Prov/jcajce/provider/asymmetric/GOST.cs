using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.jcajce.provider.asymmetric
{
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.gost.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class GOST
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".gost.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyPairGenerator.GOST3410", PREFIX + "KeyPairGeneratorSpi");
				provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-94", "GOST3410");

				provider.addAlgorithm("KeyFactory.GOST3410", PREFIX + "KeyFactorySpi");
				provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-94", "GOST3410");


				provider.addAlgorithm("AlgorithmParameters.GOST3410", PREFIX + "AlgorithmParametersSpi");
				provider.addAlgorithm("AlgorithmParameterGenerator.GOST3410", PREFIX + "AlgorithmParameterGeneratorSpi");

				registerOid(provider, CryptoProObjectIdentifiers_Fields.gostR3410_94, "GOST3410", new KeyFactorySpi());
				registerOidAlgorithmParameterGenerator(provider, CryptoProObjectIdentifiers_Fields.gostR3410_94, "GOST3410");

				provider.addAlgorithm("Signature.GOST3410", PREFIX + "SignatureSpi");
				provider.addAlgorithm("Alg.Alias.Signature.GOST-3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-94", "GOST3410");
				provider.addAlgorithm("Alg.Alias.Signature.GOST3411withGOST3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.Signature.GOST3411WITHGOST3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.Signature.GOST3411WithGOST3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.Signature." + CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3410");


				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.GOST-3410", "GOST3410");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.GOST-3410", "GOST3410");
			}
		}
	}

}