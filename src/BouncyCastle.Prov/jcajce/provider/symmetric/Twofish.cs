namespace org.bouncycastle.jcajce.provider.symmetric
{
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

	public sealed class Twofish
	{
		private Twofish()
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
					return new TwofishEngine();
				}
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("Twofish", 256, new CipherKeyGenerator())
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new TwofishEngine())))
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new TwofishEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-Twofish", 256, new Poly1305KeyGenerator())
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAndTwofish-CBC
		/// </summary>
		public class PBEWithSHAKeyFactory : PBESecretKeyFactory
		{
			public PBEWithSHAKeyFactory() : base("PBEwithSHAandTwofish-CBC", null, true, PKCS12, SHA1, 256, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAndTwofish-CBC
		/// </summary>
		public class PBEWithSHA : BaseBlockCipher
		{
			public PBEWithSHA() : base(new CBCBlockCipher(new TwofishEngine()), PKCS12, SHA1, 256, 16)
			{
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "Twofish IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Twofish).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.Twofish", PREFIX + "$ECB");
				provider.addAlgorithm("KeyGenerator.Twofish", PREFIX + "$KeyGen");
				provider.addAlgorithm("AlgorithmParameters.Twofish", PREFIX + "$AlgParams");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH-CBC", "PKCS12PBE");
				provider.addAlgorithm("Cipher.PBEWITHSHAANDTWOFISH-CBC", PREFIX + "$PBEWithSHA");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAANDTWOFISH-CBC", PREFIX + "$PBEWithSHAKeyFactory");

				addGMacAlgorithm(provider, "Twofish", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "Twofish", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}