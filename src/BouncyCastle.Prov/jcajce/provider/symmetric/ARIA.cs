using org.bouncycastle.asn1.nsri;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using CCMParameters = org.bouncycastle.asn1.cms.CCMParameters;
	using GCMParameters = org.bouncycastle.asn1.cms.GCMParameters;
	using NSRIObjectIdentifiers = org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using ARIAEngine = org.bouncycastle.crypto.engines.ARIAEngine;
	using ARIAWrapEngine = org.bouncycastle.crypto.engines.ARIAWrapEngine;
	using ARIAWrapPadEngine = org.bouncycastle.crypto.engines.ARIAWrapPadEngine;
	using RFC3211WrapEngine = org.bouncycastle.crypto.engines.RFC3211WrapEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using GCMBlockCipher = org.bouncycastle.crypto.modes.GCMBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using BlockCipherProvider = org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
	using IvAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
	using AEADParameterSpec = org.bouncycastle.jcajce.spec.AEADParameterSpec;

	public sealed class ARIA
	{
		private ARIA()
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
					return new ARIAEngine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new ARIAEngine()), 128)
			{
			}
		}

		public class CFB : BaseBlockCipher
		{
			public CFB() : base(new BufferedBlockCipher(new CFBBlockCipher(new ARIAEngine(), 128)), 128)
			{
			}
		}

		public class OFB : BaseBlockCipher
		{
			public OFB() : base(new BufferedBlockCipher(new OFBBlockCipher(new ARIAEngine(), 128)), 128)
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new ARIAWrapEngine())
			{
			}
		}

		public class WrapPad : BaseWrapCipher
		{
			public WrapPad() : base(new ARIAWrapPadEngine())
			{
			}
		}

		public class RFC3211Wrap : BaseWrapCipher
		{
			public RFC3211Wrap() : base(new RFC3211WrapEngine(new ARIAEngine()), 16)
			{
			}
		}

		public class GMAC : BaseMac
		{
			public GMAC() : base(new GMac(new GCMBlockCipher(new ARIAEngine())))
			{
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("ARIA", null)
			{
			}
		}
		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new ARIAEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-ARIA", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(256)
			{
			}

			public KeyGen(int keySize) : base("ARIA", keySize, new CipherKeyGenerator())
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
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for ARIA parameter generation.");
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
					@params = createParametersInstance("ARIA");
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
				return "ARIA IV";
			}
		}

		public class AlgParamsGCM : BaseAlgorithmParameters
		{
			internal GCMParameters gcmParams;

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (GcmSpecUtil.isGcmSpec(paramSpec))
				{
					gcmParams = GcmSpecUtil.extractGcmParameters(paramSpec);
				}
				else if (paramSpec is AEADParameterSpec)
				{
					gcmParams = new GCMParameters(((AEADParameterSpec)paramSpec).getNonce(), ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
				}
				else
				{
					throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + paramSpec.GetType().getName());
				}
			}

			public virtual void engineInit(byte[] @params)
			{
				gcmParams = GCMParameters.getInstance(@params);
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (!isASN1FormatString(format))
				{
					throw new IOException("unknown format specified");
				}

				gcmParams = GCMParameters.getInstance(@params);
			}

			public virtual byte[] engineGetEncoded()
			{
				return gcmParams.getEncoded();
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (!isASN1FormatString(format))
				{
					throw new IOException("unknown format specified");
				}

				return gcmParams.getEncoded();
			}

			public virtual string engineToString()
			{
				return "GCM";
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(AlgorithmParameterSpec) || GcmSpecUtil.isGcmSpec(paramSpec))
				{
					if (GcmSpecUtil.gcmSpecExists())
					{
						return GcmSpecUtil.extractGcmSpec(gcmParams.toASN1Primitive());
					}
					return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
				}
				if (paramSpec == typeof(AEADParameterSpec))
				{
					return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
				}
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(gcmParams.getNonce());
				}

				throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
			}
		}

		public class AlgParamsCCM : BaseAlgorithmParameters
		{
			internal CCMParameters ccmParams;

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (GcmSpecUtil.isGcmSpec(paramSpec))
				{
					ccmParams = CCMParameters.getInstance(GcmSpecUtil.extractGcmParameters(paramSpec));
				}
				else if (paramSpec is AEADParameterSpec)
				{
					ccmParams = new CCMParameters(((AEADParameterSpec)paramSpec).getNonce(), ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
				}
				else
				{
					throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + paramSpec.GetType().getName());
				}
			}

			public virtual void engineInit(byte[] @params)
			{
				ccmParams = CCMParameters.getInstance(@params);
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (!isASN1FormatString(format))
				{
					throw new IOException("unknown format specified");
				}

				ccmParams = CCMParameters.getInstance(@params);
			}

			public virtual byte[] engineGetEncoded()
			{
				return ccmParams.getEncoded();
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (!isASN1FormatString(format))
				{
					throw new IOException("unknown format specified");
				}

				return ccmParams.getEncoded();
			}

			public virtual string engineToString()
			{
				return "CCM";
			}

			public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(AlgorithmParameterSpec) || GcmSpecUtil.isGcmSpec(paramSpec))
				{
					if (GcmSpecUtil.gcmSpecExists())
					{
						return GcmSpecUtil.extractGcmSpec(ccmParams.toASN1Primitive());
					}
					return new AEADParameterSpec(ccmParams.getNonce(), ccmParams.getIcvLen() * 8);
				}
				if (paramSpec == typeof(AEADParameterSpec))
				{
					return new AEADParameterSpec(ccmParams.getNonce(), ccmParams.getIcvLen() * 8);
				}
				if (paramSpec == typeof(IvParameterSpec))
				{
					return new IvParameterSpec(ccmParams.getNonce());
				}

				throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
			}
		}

		public class Mappings : SymmetricAlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(ARIA).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.ARIA", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NSRIObjectIdentifiers_Fields.id_aria128_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NSRIObjectIdentifiers_Fields.id_aria192_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", NSRIObjectIdentifiers_Fields.id_aria256_cbc, "ARIA");

				provider.addAlgorithm("AlgorithmParameterGenerator.ARIA", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria128_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria192_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria256_cbc, "ARIA");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria128_ofb, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria192_ofb, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria256_ofb, "ARIA");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria128_cfb, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria192_cfb, "ARIA");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator", NSRIObjectIdentifiers_Fields.id_aria256_cfb, "ARIA");


				provider.addAlgorithm("Cipher.ARIA", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria128_ecb, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria192_ecb, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria256_ecb, PREFIX + "$ECB");

				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria128_cbc, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria192_cbc, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria256_cbc, PREFIX + "$CBC");

				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria128_cfb, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria192_cfb, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria256_cfb, PREFIX + "$CFB");

				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria128_ofb, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria192_ofb, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", NSRIObjectIdentifiers_Fields.id_aria256_ofb, PREFIX + "$OFB");

				provider.addAlgorithm("Cipher.ARIARFC3211WRAP", PREFIX + "$RFC3211Wrap");

				provider.addAlgorithm("Cipher.ARIAWRAP", PREFIX + "$Wrap");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria128_kw, "ARIAWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria192_kw, "ARIAWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria256_kw, "ARIAWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher.ARIAKW", "ARIAWRAP");

				provider.addAlgorithm("Cipher.ARIAWRAPPAD", PREFIX + "$WrapPad");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria128_kwp, "ARIAWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria192_kwp, "ARIAWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria256_kwp, "ARIAWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher.ARIAKWP", "ARIAWRAPPAD");

				provider.addAlgorithm("KeyGenerator.ARIA", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_kw, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_kw, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_kw, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_kwp, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_kwp, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_kwp, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_ecb, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_ecb, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_ecb, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_cbc, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_cbc, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_cbc, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_cfb, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_cfb, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_cfb, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_ofb, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_ofb, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_ofb, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_ccm, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_ccm, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_ccm, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria128_gcm, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria192_gcm, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NSRIObjectIdentifiers_Fields.id_aria256_gcm, PREFIX + "$KeyGen256");

				provider.addAlgorithm("SecretKeyFactory.ARIA", PREFIX + "$KeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NSRIObjectIdentifiers_Fields.id_aria128_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NSRIObjectIdentifiers_Fields.id_aria192_cbc, "ARIA");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", NSRIObjectIdentifiers_Fields.id_aria256_cbc, "ARIA");

				provider.addAlgorithm("AlgorithmParameterGenerator.ARIACCM", PREFIX + "$AlgParamGenCCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria128_ccm, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria192_ccm, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria256_ccm, "CCM");

				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria128_ccm, "CCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria192_ccm, "CCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria256_ccm, "CCM");

				provider.addAlgorithm("AlgorithmParameterGenerator.ARIAGCM", PREFIX + "$AlgParamGenGCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria128_gcm, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria192_gcm, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NSRIObjectIdentifiers_Fields.id_aria256_gcm, "GCM");

				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria128_gcm, "GCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria192_gcm, "GCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NSRIObjectIdentifiers_Fields.id_aria256_gcm, "GCM");

				addGMacAlgorithm(provider, "ARIA", PREFIX + "$GMAC", PREFIX + "$KeyGen");
				addPoly1305Algorithm(provider, "ARIA", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}