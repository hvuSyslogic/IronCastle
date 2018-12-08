namespace org.bouncycastle.jcajce.provider.symmetric
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CAST6Engine = org.bouncycastle.crypto.engines.CAST6Engine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public sealed class CAST6
	{
		private CAST6()
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
					return new CAST6Engine();
				}
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("CAST6", 256, new CipherKeyGenerator())
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new CAST6Engine())))
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new CAST6Engine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-CAST6", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "CAST6 IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(CAST6).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.CAST6", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.CAST6", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.CAST6", PREFIX + "$AlgParams");

				addGMacAlgorithm(provider, "CAST6", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "CAST6", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}