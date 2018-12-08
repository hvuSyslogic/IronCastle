using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;

	public class McEliece
	{
		private const string PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".mceliece.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyPairGenerator.McElieceKobaraImai", PREFIX + "McElieceCCA2KeyPairGeneratorSpi");
				provider.addAlgorithm("KeyPairGenerator.McEliecePointcheval", PREFIX + "McElieceCCA2KeyPairGeneratorSpi");
				provider.addAlgorithm("KeyPairGenerator.McElieceFujisaki", PREFIX + "McElieceCCA2KeyPairGeneratorSpi");
				provider.addAlgorithm("KeyPairGenerator.McEliece", PREFIX + "McElieceKeyPairGeneratorSpi");
				provider.addAlgorithm("KeyPairGenerator.McEliece-CCA2", PREFIX + "McElieceCCA2KeyPairGeneratorSpi");

				provider.addAlgorithm("KeyFactory.McElieceKobaraImai", PREFIX + "McElieceCCA2KeyFactorySpi");
				provider.addAlgorithm("KeyFactory.McEliecePointcheval", PREFIX + "McElieceCCA2KeyFactorySpi");
				provider.addAlgorithm("KeyFactory.McElieceFujisaki", PREFIX + "McElieceCCA2KeyFactorySpi");
				provider.addAlgorithm("KeyFactory.McEliece", PREFIX + "McElieceKeyFactorySpi");
				provider.addAlgorithm("KeyFactory.McEliece-CCA2", PREFIX + "McElieceCCA2KeyFactorySpi");

				provider.addAlgorithm("KeyFactory." + PQCObjectIdentifiers_Fields.mcElieceCca2, PREFIX + "McElieceCCA2KeyFactorySpi");
				provider.addAlgorithm("KeyFactory." + PQCObjectIdentifiers_Fields.mcEliece, PREFIX + "McElieceKeyFactorySpi");

				provider.addAlgorithm("Cipher.McEliece", PREFIX + "McEliecePKCSCipherSpi$McEliecePKCS");
				provider.addAlgorithm("Cipher.McEliecePointcheval", PREFIX + "McEliecePointchevalCipherSpi$McEliecePointcheval");
				provider.addAlgorithm("Cipher.McElieceKobaraImai", PREFIX + "McElieceKobaraImaiCipherSpi$McElieceKobaraImai");
				provider.addAlgorithm("Cipher.McElieceFujisaki", PREFIX + "McElieceFujisakiCipherSpi$McElieceFujisaki");
			}
		}
	}

}