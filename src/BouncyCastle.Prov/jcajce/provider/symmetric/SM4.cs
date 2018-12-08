using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SM4Engine = org.bouncycastle.crypto.engines.SM4Engine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public sealed class SM4
	{
		private SM4()
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
					return new SM4Engine();
				}
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("SM4", 128, new CipherKeyGenerator())
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new SM4Engine()))
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new SM4Engine())))
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new SM4Engine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-SM4", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SM4 parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[16];

				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("SM4");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class AlgParams : IvAlgorithmParameters
		{
			public override string engineToString()
			{
				return "SM4 IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SM4).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.SM4", PREFIX + "$AlgParams");

				provider.addAlgorithm("AlgorithmParameterGenerator.SM4", PREFIX + "$AlgParamGen");

				provider.addAlgorithm("Cipher.SM4", PREFIX + "$ECB");

				provider.addAlgorithm("KeyGenerator.SM4", PREFIX + "$KeyGen");

				addCMacAlgorithm(provider, "SM4", PREFIX + "$CMAC", PREFIX + "$KeyGen");
				addGMacAlgorithm(provider, "SM4", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "SM4", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}