namespace org.bouncycastle.jcajce.provider.symmetric
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public abstract class SymmetricAlgorithmProvider : AlgorithmProvider
	{
		public virtual void addCMacAlgorithm(ConfigurableProvider provider, string algorithm, string algorithmClassName, string keyGeneratorClassName)
		{
			provider.addAlgorithm("Mac." + algorithm + "-CMAC", algorithmClassName);
			provider.addAlgorithm("Alg.Alias.Mac." + algorithm + "CMAC", algorithm + "-CMAC");

			provider.addAlgorithm("KeyGenerator." + algorithm + "-CMAC", keyGeneratorClassName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator." + algorithm + "CMAC", algorithm + "-CMAC");
		}

		public virtual void addGMacAlgorithm(ConfigurableProvider provider, string algorithm, string algorithmClassName, string keyGeneratorClassName)
		{
			provider.addAlgorithm("Mac." + algorithm + "-GMAC", algorithmClassName);
			provider.addAlgorithm("Alg.Alias.Mac." + algorithm + "GMAC", algorithm + "-GMAC");

			provider.addAlgorithm("KeyGenerator." + algorithm + "-GMAC", keyGeneratorClassName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator." + algorithm + "GMAC", algorithm + "-GMAC");
		}

		public virtual void addPoly1305Algorithm(ConfigurableProvider provider, string algorithm, string algorithmClassName, string keyGeneratorClassName)
		{
			provider.addAlgorithm("Mac.POLY1305-" + algorithm, algorithmClassName);
			provider.addAlgorithm("Alg.Alias.Mac.POLY1305" + algorithm, "POLY1305-" + algorithm);

			provider.addAlgorithm("KeyGenerator.POLY1305-" + algorithm, keyGeneratorClassName);
			provider.addAlgorithm("Alg.Alias.KeyGenerator.POLY1305" + algorithm, "POLY1305-" + algorithm);
		}

	}

}