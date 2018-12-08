namespace org.bouncycastle.jcajce.provider.symmetric
{
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using ThreefishEngine = org.bouncycastle.crypto.engines.ThreefishEngine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class Threefish
	{
		private Threefish()
		{
		}

		public class ECB_256 : BaseBlockCipher
		{
			public ECB_256() : base(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256))
			{
			}
		}

		public class ECB_512 : BaseBlockCipher
		{
			public ECB_512() : base(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512))
			{
			}
		}

		public class ECB_1024 : BaseBlockCipher
		{
			public ECB_1024() : base(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024))
			{
			}
		}

		public class KeyGen_256 : BaseKeyGenerator
		{
			public KeyGen_256() : base("Threefish-256", 256, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGen_512 : BaseKeyGenerator
		{
			public KeyGen_512() : base("Threefish-512", 512, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGen_1024 : BaseKeyGenerator
		{
			public KeyGen_1024() : base("Threefish-1024", 1024, new CipherKeyGenerator())
			{
			}
		}

		public class AlgParams_256 : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Threefish-256 IV";
			}
		}

		public class AlgParams_512 : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Threefish-512 IV";
			}
		}

		public class AlgParams_1024 : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Threefish-1024 IV";
			}
		}

		public class CMAC_256 : BaseMac
		{
			public CMAC_256() : base(new CMac(new ThreefishEngine(256)))
			{
			}
		}

		public class CMAC_512 : BaseMac
		{
			public CMAC_512() : base(new CMac(new ThreefishEngine(512)))
			{
			}
		}

		public class CMAC_1024 : BaseMac
		{
			public CMAC_1024() : base(new CMac(new ThreefishEngine(1024)))
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Threefish).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Mac.Threefish-256CMAC", PREFIX + "$CMAC_256");
				provider.addAlgorithm("Mac.Threefish-512CMAC", PREFIX + "$CMAC_512");
				provider.addAlgorithm("Mac.Threefish-1024CMAC", PREFIX + "$CMAC_1024");

				provider.addAlgorithm("Cipher.Threefish-256", PREFIX + "$ECB_256");
				provider.addAlgorithm("Cipher.Threefish-512", PREFIX + "$ECB_512");
				provider.addAlgorithm("Cipher.Threefish-1024", PREFIX + "$ECB_1024");
				provider.addAlgorithm("KeyGenerator.Threefish-256", PREFIX + "$KeyGen_256");
				provider.addAlgorithm("KeyGenerator.Threefish-512", PREFIX + "$KeyGen_512");
				provider.addAlgorithm("KeyGenerator.Threefish-1024", PREFIX + "$KeyGen_1024");
				provider.addAlgorithm("AlgorithmParameters.Threefish-256", PREFIX + "$AlgParams_256");
				provider.addAlgorithm("AlgorithmParameters.Threefish-512", PREFIX + "$AlgParams_512");
				provider.addAlgorithm("AlgorithmParameters.Threefish-1024", PREFIX + "$AlgParams_1024");
			}
		}
	}

}