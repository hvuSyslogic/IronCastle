namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using XTEAEngine = org.bouncycastle.crypto.engines.XTEAEngine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class XTEA
	{
		private XTEA()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new XTEAEngine())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("XTEA", 128, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "XTEA IV";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(XTEA).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.XTEA", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.XTEA", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.XTEA", PREFIX + "$AlgParams");

			}
		}
	}

}