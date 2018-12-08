using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.jcajce.provider.asymmetric
{
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using KeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyFactorySpi;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

	public class ElGamal
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".elgamal.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameterGenerator.ELGAMAL", PREFIX + "AlgorithmParameterGeneratorSpi");
				provider.addAlgorithm("AlgorithmParameterGenerator.ElGamal", PREFIX + "AlgorithmParameterGeneratorSpi");
				provider.addAlgorithm("AlgorithmParameters.ELGAMAL", PREFIX + "AlgorithmParametersSpi");
				provider.addAlgorithm("AlgorithmParameters.ElGamal", PREFIX + "AlgorithmParametersSpi");

				provider.addAlgorithm("Cipher.ELGAMAL", PREFIX + "CipherSpi$NoPadding");
				provider.addAlgorithm("Cipher.ElGamal", PREFIX + "CipherSpi$NoPadding");
				provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/ECB/PKCS1PADDING", "ELGAMAL/PKCS1");
				provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/PKCS1PADDING", "ELGAMAL/PKCS1");
				provider.addAlgorithm("Alg.Alias.Cipher.ELGAMAL/NONE/NOPADDING", "ELGAMAL");

				provider.addAlgorithm("Cipher.ELGAMAL/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
				provider.addAlgorithm("KeyFactory.ELGAMAL", PREFIX + "KeyFactorySpi");
				provider.addAlgorithm("KeyFactory.ElGamal", PREFIX + "KeyFactorySpi");

				provider.addAlgorithm("KeyPairGenerator.ELGAMAL", PREFIX + "KeyPairGeneratorSpi");
				provider.addAlgorithm("KeyPairGenerator.ElGamal", PREFIX + "KeyPairGeneratorSpi");

				AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();

				registerOid(provider, OIWObjectIdentifiers_Fields.elGamalAlgorithm, "ELGAMAL", keyFact);
				registerOidAlgorithmParameterGenerator(provider, OIWObjectIdentifiers_Fields.elGamalAlgorithm, "ELGAMAL");
			}
		}
	}

}