namespace org.bouncycastle.jcajce.provider.keystore
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	public class BC
	{
		private const string PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".bc.";

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyStore.BKS", PREFIX + "BcKeyStoreSpi$Std");
				provider.addAlgorithm("KeyStore.BKS-V1", PREFIX + "BcKeyStoreSpi$Version1");
				provider.addAlgorithm("KeyStore.BouncyCastle", PREFIX + "BcKeyStoreSpi$BouncyCastleStore");
				provider.addAlgorithm("Alg.Alias.KeyStore.UBER", "BouncyCastle");
				provider.addAlgorithm("Alg.Alias.KeyStore.BOUNCYCASTLE", "BouncyCastle");
				provider.addAlgorithm("Alg.Alias.KeyStore.bouncycastle", "BouncyCastle");
			}
		}
	}

}