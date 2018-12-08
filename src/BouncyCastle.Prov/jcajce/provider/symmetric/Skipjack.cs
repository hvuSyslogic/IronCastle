namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using SkipjackEngine = org.bouncycastle.crypto.engines.SkipjackEngine;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Skipjack
	{
		private Skipjack()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new SkipjackEngine())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Skipjack", 80, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Skipjack IV";
			}
		}

		public class Mac : BaseMac
		{
			public Mac() : base(new CBCBlockCipherMac(new SkipjackEngine()))
			{
			}
		}

		public class MacCFB8 : BaseMac
		{
			public MacCFB8() : base(new CFBBlockCipherMac(new SkipjackEngine()))
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Skipjack).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.SKIPJACK", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.SKIPJACK", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.SKIPJACK", PREFIX + "$AlgParams");
				provider.addAlgorithm("Mac.SKIPJACKMAC", PREFIX + "$Mac");
				provider.addAlgorithm("Alg.Alias.Mac.SKIPJACK", "SKIPJACKMAC");
				provider.addAlgorithm("Mac.SKIPJACKMAC/CFB8", PREFIX + "$MacCFB8");
				provider.addAlgorithm("Alg.Alias.Mac.SKIPJACK/CFB8", "SKIPJACKMAC/CFB8");

			}
		}
	}

}