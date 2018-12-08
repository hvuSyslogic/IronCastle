namespace org.bouncycastle.jcajce.provider.util
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

	public abstract class AlgorithmProvider
	{
		public abstract void configure(ConfigurableProvider provider);
	}

}