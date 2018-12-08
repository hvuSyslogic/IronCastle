using org.bouncycastle.asn1.kisa;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using SEEDEngine = org.bouncycastle.crypto.engines.SEEDEngine;
	using SEEDWrapEngine = org.bouncycastle.crypto.engines.SEEDWrapEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

	public sealed class SEED
	{
		private SEED()
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
					return new SEEDEngine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new SEEDEngine()), 128)
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new SEEDWrapEngine())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : base("SEED", 128, new CipherKeyGenerator())
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new SEEDEngine()))
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new SEEDEngine())))
			{
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("SEED", null)
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new SEEDEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-SEED", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SEED parameter generation.");
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
					@params = createParametersInstance("SEED");
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
				return "SEED IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(SEED).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("AlgorithmParameters.SEED", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + KISAObjectIdentifiers_Fields.id_seedCBC, "SEED");

				provider.addAlgorithm("AlgorithmParameterGenerator.SEED", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + KISAObjectIdentifiers_Fields.id_seedCBC, "SEED");

				provider.addAlgorithm("Cipher.SEED", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", KISAObjectIdentifiers_Fields.id_seedCBC, PREFIX + "$CBC");

				provider.addAlgorithm("Cipher.SEEDWRAP", PREFIX + "$Wrap");
				provider.addAlgorithm("Alg.Alias.Cipher", KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap, "SEEDWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher.SEEDKW", "SEEDWRAP");

				provider.addAlgorithm("KeyGenerator.SEED", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", KISAObjectIdentifiers_Fields.id_seedCBC, PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap, PREFIX + "$KeyGen");

				provider.addAlgorithm("SecretKeyFactory.SEED", PREFIX + "$KeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", KISAObjectIdentifiers_Fields.id_seedCBC, "SEED");

				addCMacAlgorithm(provider, "SEED", PREFIX + "$CMAC", PREFIX + "$KeyGen");
				addGMacAlgorithm(provider, "SEED", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "SEED", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}