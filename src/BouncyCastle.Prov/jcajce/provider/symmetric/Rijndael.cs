namespace org.bouncycastle.jcajce.provider.symmetric
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using RijndaelEngine = org.bouncycastle.crypto.engines.RijndaelEngine;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Rijndael
	{
		private Rijndael()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new BlockCipherProviderAnonymousInnerClass())
			{
			}

			public class BlockCipherProviderAnonymousInnerClass : BlockCipherProvider
			{
				public BlockCipher get()
				{
					return new RijndaelEngine();
				}
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Rijndael", 192, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Rijndael IV";
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Rijndael).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.RIJNDAEL", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.RIJNDAEL", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.RIJNDAEL", PREFIX + "$AlgParams");

			}
		}
	}

}