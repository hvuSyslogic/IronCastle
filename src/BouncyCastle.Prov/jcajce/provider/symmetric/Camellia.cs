using org.bouncycastle.asn1.ntt;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using CamelliaEngine = org.bouncycastle.crypto.engines.CamelliaEngine;
	using CamelliaWrapEngine = org.bouncycastle.crypto.engines.CamelliaWrapEngine;
	using RFC3211WrapEngine = org.bouncycastle.crypto.engines.RFC3211WrapEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
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

	public sealed class Camellia
	{
		private Camellia()
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
					return new CamelliaEngine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new CamelliaEngine()), 128)
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new CamelliaWrapEngine())
			{
			}
		}

		public class RFC3211Wrap : BaseWrapCipher
		{
			public RFC3211Wrap() : base(new RFC3211WrapEngine(new CamelliaEngine()), 16)
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new CamelliaEngine())))
			{
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("Camellia", null)
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new CamelliaEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-Camellia", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(256)
			{
			}

			public KeyGen(int keySize) : base("Camellia", keySize, new CipherKeyGenerator())
			{
			}
		}

		public class KeyGen128 : KeyGen
		{
			public KeyGen128() : base(128)
			{
			}
		}

		public class KeyGen192 : KeyGen
		{
			public KeyGen192() : base(192)
			{
			}
		}

		public class KeyGen256 : KeyGen
		{
			public KeyGen256() : base(256)
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for Camellia parameter generation.");
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
					@params = createParametersInstance("Camellia");
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
				return "Camellia IV";
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(Camellia).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("AlgorithmParameters.CAMELLIA", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NTTObjectIdentifiers_Fields.id_camellia128_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NTTObjectIdentifiers_Fields.id_camellia192_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NTTObjectIdentifiers_Fields.id_camellia256_cbc, "CAMELLIA");

				provider.addAlgorithm("AlgorithmParameterGenerator.CAMELLIA", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NTTObjectIdentifiers_Fields.id_camellia128_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NTTObjectIdentifiers_Fields.id_camellia192_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NTTObjectIdentifiers_Fields.id_camellia256_cbc, "CAMELLIA");

				provider.addAlgorithm("Cipher.CAMELLIA", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NTTObjectIdentifiers_Fields.id_camellia128_cbc, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NTTObjectIdentifiers_Fields.id_camellia192_cbc, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NTTObjectIdentifiers_Fields.id_camellia256_cbc, PREFIX + "$CBC");

				provider.addAlgorithm("Cipher.CAMELLIARFC3211WRAP", PREFIX + "$RFC3211Wrap");
				provider.addAlgorithm("Cipher.CAMELLIAWRAP", PREFIX + "$Wrap");
				provider.addAlgorithm("Alg.Alias.Cipher", NTTObjectIdentifiers_Fields.id_camellia128_wrap, "CAMELLIAWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NTTObjectIdentifiers_Fields.id_camellia192_wrap, "CAMELLIAWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NTTObjectIdentifiers_Fields.id_camellia256_wrap, "CAMELLIAWRAP");

				provider.addAlgorithm("SecretKeyFactory.CAMELLIA", PREFIX + "$KeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NTTObjectIdentifiers_Fields.id_camellia128_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NTTObjectIdentifiers_Fields.id_camellia192_cbc, "CAMELLIA");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NTTObjectIdentifiers_Fields.id_camellia256_cbc, "CAMELLIA");

				provider.addAlgorithm("KeyGenerator.CAMELLIA", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia128_wrap, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia192_wrap, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia256_wrap, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia128_cbc, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia192_cbc, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NTTObjectIdentifiers_Fields.id_camellia256_cbc, PREFIX + "$KeyGen256");

				addGMacAlgorithm(provider, "CAMELLIA", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "CAMELLIA", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}