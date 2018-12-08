namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using TEAEngine = org.bouncycastle.crypto.engines.TEAEngine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class TEA
	{
		private TEA()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new TEAEngine())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("TEA", 128, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "TEA IV";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(TEA).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.TEA", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.TEA", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.TEA", PREFIX + "$AlgParams");

			}
		}
	}

}