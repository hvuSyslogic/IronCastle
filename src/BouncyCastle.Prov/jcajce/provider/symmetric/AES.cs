using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.bc;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using CCMParameters = org.bouncycastle.asn1.cms.CCMParameters;
	using GCMParameters = org.bouncycastle.asn1.cms.GCMParameters;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherKeyGenerator = org.bouncycastle.crypto.CipherKeyGenerator;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using Mac = org.bouncycastle.crypto.Mac;
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using AESWrapEngine = org.bouncycastle.crypto.engines.AESWrapEngine;
	using AESWrapPadEngine = org.bouncycastle.crypto.engines.AESWrapPadEngine;
	using RFC3211WrapEngine = org.bouncycastle.crypto.engines.RFC3211WrapEngine;
	using RFC5649WrapEngine = org.bouncycastle.crypto.engines.RFC5649WrapEngine;
	using Poly1305KeyGenerator = org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using GMac = org.bouncycastle.crypto.macs.GMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CCMBlockCipher = org.bouncycastle.crypto.modes.CCMBlockCipher;
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
	using PBESecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;
	using AEADParameterSpec = org.bouncycastle.jcajce.spec.AEADParameterSpec;

	public sealed class AES
	{
		private static readonly Map<string, string> generalAesAttributes = new HashMap<string, string>();

		static AES()
		{
			generalAesAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
			generalAesAttributes.put("SupportedKeyFormats", "RAW");
		}

		private AES()
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
					return new AESEngine();
				}
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new AESEngine()), 128)
			{
			}
		}

		public class CFB : BaseBlockCipher
		{
			public CFB() : base(new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), 128)), 128)
			{
			}
		}

		public class OFB : BaseBlockCipher
		{
			public OFB() : base(new BufferedBlockCipher(new OFBBlockCipher(new AESEngine(), 128)), 128)
			{
			}
		}

		public class GCM : BaseBlockCipher
		{
			public GCM() : base(new GCMBlockCipher(new AESEngine()))
			{
			}
		}

		public class CCM : BaseBlockCipher
		{
			public CCM() : base(new CCMBlockCipher(new AESEngine()), false, 16)
			{
			}
		}

		public class AESCMAC : BaseMac
		{
			public AESCMAC() : base(new CMac(new AESEngine()))
			{
			}
		}

		public class AESGMAC : BaseMac
		{
			public AESGMAC() : base(new GMac(new GCMBlockCipher(new AESEngine())))
			{
			}
		}

		public class AESCCMMAC : BaseMac
		{
			public AESCCMMAC() : base(new CCMMac())
			{
			}

			public class CCMMac : Mac
			{
				internal readonly CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());

				internal int macLength = 8;

				public virtual void init(CipherParameters @params)
				{
					ccm.init(true, @params);

					this.macLength = ccm.getMac().Length;
				}

				public virtual string getAlgorithmName()
				{
					return ccm.getAlgorithmName() + "Mac";
				}

				public virtual int getMacSize()
				{
					return macLength;
				}

				public virtual void update(byte @in)
				{
					ccm.processAADByte(@in);
				}

				public virtual void update(byte[] @in, int inOff, int len)
				{
					ccm.processAADBytes(@in, inOff, len);
				}

				public virtual int doFinal(byte[] @out, int outOff)
				{
					try
					{
						return ccm.doFinal(@out, 0);
					}
					catch (InvalidCipherTextException e)
					{
						throw new IllegalStateException("exception on doFinal(): " + e.ToString());
					}
				}

				public virtual void reset()
				{
					ccm.reset();
				}
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("AES", null)
			{
			}
		}

		public class Poly1305 : BaseMac
		{
			public Poly1305() : base(new org.bouncycastle.crypto.macs.Poly1305(new AESEngine()))
			{
			}
		}

		public class Poly1305KeyGen : BaseKeyGenerator
		{
			public Poly1305KeyGen() : base("Poly1305-AES", 256, new Poly1305KeyGenerator())
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new AESWrapEngine())
			{
			}
		}

		public class WrapPad : BaseWrapCipher
		{
			public WrapPad() : base(new AESWrapPadEngine())
			{
			}
		}

		public class RFC3211Wrap : BaseWrapCipher
		{
			public RFC3211Wrap() : base(new RFC3211WrapEngine(new AESEngine()), 16)
			{
			}
		}

		public class RFC5649Wrap : BaseWrapCipher
		{
			public RFC5649Wrap() : base(new RFC5649WrapEngine(new AESEngine()))
			{
			}
		}

		/// <summary>
		/// PBEWithAES-CBC
		/// </summary>
		public class PBEWithAESCBC : BaseBlockCipher
		{
			public PBEWithAESCBC() : base(new CBCBlockCipher(new AESEngine()))
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1AES-CBC
		/// </summary>
		public class PBEWithSHA1AESCBC128 : BaseBlockCipher
		{
			public PBEWithSHA1AESCBC128() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA1, 128, 16)
			{
			}
		}

		public class PBEWithSHA1AESCBC192 : BaseBlockCipher
		{
			public PBEWithSHA1AESCBC192() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA1, 192, 16)
			{
			}
		}

		public class PBEWithSHA1AESCBC256 : BaseBlockCipher
		{
			public PBEWithSHA1AESCBC256() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA1, 256, 16)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA256AES-CBC
		/// </summary>
		public class PBEWithSHA256AESCBC128 : BaseBlockCipher
		{
			public PBEWithSHA256AESCBC128() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA256, 128, 16)
			{
			}
		}

		public class PBEWithSHA256AESCBC192 : BaseBlockCipher
		{
			public PBEWithSHA256AESCBC192() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA256, 192, 16)
			{
			}
		}

		public class PBEWithSHA256AESCBC256 : BaseBlockCipher
		{
			public PBEWithSHA256AESCBC256() : base(new CBCBlockCipher(new AESEngine()), PKCS12, SHA256, 256, 16)
			{
			}
		}

		public class KeyGen : BaseKeyGenerator
		{
			public KeyGen() : this(192)
			{
			}

			public KeyGen(int keySize) : base("AES", keySize, new CipherKeyGenerator())
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

		/// <summary>
		/// PBEWithSHA1And128BitAES-BC
		/// </summary>
		public class PBEWithSHAAnd128BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHAAnd128BitAESBC() : base("PBEWithSHA1And128BitAES-CBC-BC", null, true, PKCS12, SHA1, 128, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1And192BitAES-BC
		/// </summary>
		public class PBEWithSHAAnd192BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHAAnd192BitAESBC() : base("PBEWithSHA1And192BitAES-CBC-BC", null, true, PKCS12, SHA1, 192, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1And256BitAES-BC
		/// </summary>
		public class PBEWithSHAAnd256BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHAAnd256BitAESBC() : base("PBEWithSHA1And256BitAES-CBC-BC", null, true, PKCS12, SHA1, 256, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA256And128BitAES-BC
		/// </summary>
		public class PBEWithSHA256And128BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHA256And128BitAESBC() : base("PBEWithSHA256And128BitAES-CBC-BC", null, true, PKCS12, SHA256, 128, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA256And192BitAES-BC
		/// </summary>
		public class PBEWithSHA256And192BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHA256And192BitAESBC() : base("PBEWithSHA256And192BitAES-CBC-BC", null, true, PKCS12, SHA256, 192, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA256And256BitAES-BC
		/// </summary>
		public class PBEWithSHA256And256BitAESBC : PBESecretKeyFactory
		{
			public PBEWithSHA256And256BitAESBC() : base("PBEWithSHA256And256BitAES-CBC-BC", null, true, PKCS12, SHA256, 256, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithMD5And128BitAES-OpenSSL
		/// </summary>
		public class PBEWithMD5And128BitAESCBCOpenSSL : PBESecretKeyFactory
		{
			public PBEWithMD5And128BitAESCBCOpenSSL() : base("PBEWithMD5And128BitAES-CBC-OpenSSL", null, true, OPENSSL, MD5, 128, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithMD5And192BitAES-OpenSSL
		/// </summary>
		public class PBEWithMD5And192BitAESCBCOpenSSL : PBESecretKeyFactory
		{
			public PBEWithMD5And192BitAESCBCOpenSSL() : base("PBEWithMD5And192BitAES-CBC-OpenSSL", null, true, OPENSSL, MD5, 192, 128)
			{
			}
		}

		/// <summary>
		/// PBEWithMD5And256BitAES-OpenSSL
		/// </summary>
		public class PBEWithMD5And256BitAESCBCOpenSSL : PBESecretKeyFactory
		{
			public PBEWithMD5And256BitAESCBCOpenSSL() : base("PBEWithMD5And256BitAES-CBC-OpenSSL", null, true, OPENSSL, MD5, 256, 128)
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[16];

				if (random == null)
				{
					random = new SecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("AES");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class AlgParamGenCCM : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				// TODO: add support for GCMParameterSpec as a template.
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[12];

				if (random == null)
				{
					random = new SecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("CCM");
					@params.init((new CCMParameters(iv, 12)).getEncoded());
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class AlgParamGenGCM : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				// TODO: add support for GCMParameterSpec as a template.
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] nonce = new byte[12];

				if (random == null)
				{
					random = new SecureRandom();
				}

				random.nextBytes(nonce);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("GCM");
					@params.init((new GCMParameters(nonce, 16)).getEncoded());
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
				return "AES IV";
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
			internal static readonly string PREFIX = typeof(AES).getName();

			/// <summary>
			/// These three got introduced in some messages as a result of a typo in an
			/// early document. We don't produce anything using these OID values, but we'll
			/// read them.
			/// </summary>
			internal const string wrongAES128 = "2.16.840.1.101.3.4.2";
			internal const string wrongAES192 = "2.16.840.1.101.3.4.22";
			internal const string wrongAES256 = "2.16.840.1.101.3.4.42";

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("AlgorithmParameters.AES", PREFIX + "$AlgParams");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + wrongAES128, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + wrongAES192, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + wrongAES256, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes128_CBC, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes192_CBC, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes256_CBC, "AES");

				provider.addAlgorithm("AlgorithmParameters.GCM", PREFIX + "$AlgParamsGCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes128_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes192_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes256_GCM, "GCM");

				provider.addAlgorithm("AlgorithmParameters.CCM", PREFIX + "$AlgParamsCCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes128_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes192_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers_Fields.id_aes256_CCM, "CCM");

				provider.addAlgorithm("AlgorithmParameterGenerator.AES", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + wrongAES128, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + wrongAES192, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + wrongAES256, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes128_CBC, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes192_CBC, "AES");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes256_CBC, "AES");

				provider.addAttributes("Cipher.AES", generalAesAttributes);
				provider.addAlgorithm("Cipher.AES", PREFIX + "$ECB");
				provider.addAlgorithm("Alg.Alias.Cipher." + wrongAES128, "AES");
				provider.addAlgorithm("Alg.Alias.Cipher." + wrongAES192, "AES");
				provider.addAlgorithm("Alg.Alias.Cipher." + wrongAES256, "AES");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes128_ECB, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes192_ECB, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes256_ECB, PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes128_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes192_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes256_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes128_OFB, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes192_OFB, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes256_OFB, PREFIX + "$OFB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes128_CFB, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes192_CFB, PREFIX + "$CFB");
				provider.addAlgorithm("Cipher", NISTObjectIdentifiers_Fields.id_aes256_CFB, PREFIX + "$CFB");

				provider.addAttributes("Cipher.AESWRAP", generalAesAttributes);
				provider.addAlgorithm("Cipher.AESWRAP", PREFIX + "$Wrap");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes128_wrap, "AESWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes192_wrap, "AESWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes256_wrap, "AESWRAP");
				provider.addAlgorithm("Alg.Alias.Cipher.AESKW", "AESWRAP");

				provider.addAttributes("Cipher.AESWRAPPAD", generalAesAttributes);
				provider.addAlgorithm("Cipher.AESWRAPPAD", PREFIX + "$WrapPad");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes128_wrap_pad, "AESWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes192_wrap_pad, "AESWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes256_wrap_pad, "AESWRAPPAD");
				provider.addAlgorithm("Alg.Alias.Cipher.AESKWP", "AESWRAPPAD");

				provider.addAlgorithm("Cipher.AESRFC3211WRAP", PREFIX + "$RFC3211Wrap");
				provider.addAlgorithm("Cipher.AESRFC5649WRAP", PREFIX + "$RFC5649Wrap");

				provider.addAlgorithm("AlgorithmParameterGenerator.CCM", PREFIX + "$AlgParamGenCCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes128_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes192_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes256_CCM, "CCM");

				provider.addAttributes("Cipher.CCM", generalAesAttributes);
				provider.addAlgorithm("Cipher.CCM", PREFIX + "$CCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes128_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes192_CCM, "CCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes256_CCM, "CCM");

				provider.addAlgorithm("AlgorithmParameterGenerator.GCM", PREFIX + "$AlgParamGenGCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes128_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes192_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers_Fields.id_aes256_GCM, "GCM");

				provider.addAttributes("Cipher.GCM", generalAesAttributes);
				provider.addAlgorithm("Cipher.GCM", PREFIX + "$GCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes128_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes192_GCM, "GCM");
				provider.addAlgorithm("Alg.Alias.Cipher", NISTObjectIdentifiers_Fields.id_aes256_GCM, "GCM");

				provider.addAlgorithm("KeyGenerator.AES", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator." + wrongAES128, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator." + wrongAES192, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator." + wrongAES256, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_ECB, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_CBC, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_OFB, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_CFB, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_ECB, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_CBC, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_OFB, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_CFB, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_ECB, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_CBC, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_OFB, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_CFB, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator.AESWRAP", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_wrap, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_wrap, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_wrap, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_GCM, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_GCM, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_GCM, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_CCM, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_CCM, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_CCM, PREFIX + "$KeyGen256");
				provider.addAlgorithm("KeyGenerator.AESWRAPPAD", PREFIX + "$KeyGen");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes128_wrap_pad, PREFIX + "$KeyGen128");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes192_wrap_pad, PREFIX + "$KeyGen192");
				provider.addAlgorithm("KeyGenerator", NISTObjectIdentifiers_Fields.id_aes256_wrap_pad, PREFIX + "$KeyGen256");

				provider.addAlgorithm("Mac.AESCMAC", PREFIX + "$AESCMAC");

				provider.addAlgorithm("Mac.AESCCMMAC", PREFIX + "$AESCCMMAC");
				provider.addAlgorithm("Alg.Alias.Mac." + NISTObjectIdentifiers_Fields.id_aes128_CCM.getId(), "AESCCMMAC");
				provider.addAlgorithm("Alg.Alias.Mac." + NISTObjectIdentifiers_Fields.id_aes192_CCM.getId(), "AESCCMMAC");
				provider.addAlgorithm("Alg.Alias.Mac." + NISTObjectIdentifiers_Fields.id_aes256_CCM.getId(), "AESCCMMAC");

				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes128_cbc, "PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes192_cbc, "PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes256_cbc, "PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes128_cbc, "PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes192_cbc, "PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes256_cbc, "PBEWITHSHA256AND256BITAES-CBC-BC");

				provider.addAlgorithm("Cipher.PBEWITHSHAAND128BITAES-CBC-BC", PREFIX + "$PBEWithSHA1AESCBC128");
				provider.addAlgorithm("Cipher.PBEWITHSHAAND192BITAES-CBC-BC", PREFIX + "$PBEWithSHA1AESCBC192");
				provider.addAlgorithm("Cipher.PBEWITHSHAAND256BITAES-CBC-BC", PREFIX + "$PBEWithSHA1AESCBC256");
				provider.addAlgorithm("Cipher.PBEWITHSHA256AND128BITAES-CBC-BC", PREFIX + "$PBEWithSHA256AESCBC128");
				provider.addAlgorithm("Cipher.PBEWITHSHA256AND192BITAES-CBC-BC", PREFIX + "$PBEWithSHA256AESCBC192");
				provider.addAlgorithm("Cipher.PBEWITHSHA256AND256BITAES-CBC-BC", PREFIX + "$PBEWithSHA256AESCBC256");

				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHAAND128BITAES-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHAAND192BITAES-BC", "PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHAAND256BITAES-BC", "PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND128BITAES-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND192BITAES-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND256BITAES-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND128BITAES-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND192BITAES-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-1AND256BITAES-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND128BITAES-CBC-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND192BITAES-CBC-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND256BITAES-CBC-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA256AND128BITAES-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA256AND192BITAES-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA256AND256BITAES-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND128BITAES-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND192BITAES-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA-256AND256BITAES-BC","PBEWITHSHA256AND256BITAES-CBC-BC");

				provider.addAlgorithm("Cipher.PBEWITHMD5AND128BITAES-CBC-OPENSSL", PREFIX + "$PBEWithAESCBC");
				provider.addAlgorithm("Cipher.PBEWITHMD5AND192BITAES-CBC-OPENSSL", PREFIX + "$PBEWithAESCBC");
				provider.addAlgorithm("Cipher.PBEWITHMD5AND256BITAES-CBC-OPENSSL", PREFIX + "$PBEWithAESCBC");

				provider.addAlgorithm("SecretKeyFactory.AES", PREFIX + "$KeyFactory");
				provider.addAlgorithm("SecretKeyFactory", NISTObjectIdentifiers_Fields.aes, PREFIX + "$KeyFactory");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHMD5AND128BITAES-CBC-OPENSSL", PREFIX + "$PBEWithMD5And128BitAESCBCOpenSSL");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHMD5AND192BITAES-CBC-OPENSSL", PREFIX + "$PBEWithMD5And192BitAESCBCOpenSSL");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHMD5AND256BITAES-CBC-OPENSSL", PREFIX + "$PBEWithMD5And256BitAESCBCOpenSSL");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND128BITAES-CBC-BC", PREFIX + "$PBEWithSHAAnd128BitAESBC");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND192BITAES-CBC-BC", PREFIX + "$PBEWithSHAAnd192BitAESBC");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND256BITAES-CBC-BC", PREFIX + "$PBEWithSHAAnd256BitAESBC");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHA256AND128BITAES-CBC-BC", PREFIX + "$PBEWithSHA256And128BitAESBC");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHA256AND192BITAES-CBC-BC", PREFIX + "$PBEWithSHA256And192BitAESBC");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHA256AND256BITAES-CBC-BC", PREFIX + "$PBEWithSHA256And256BitAESBC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND128BITAES-CBC-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND192BITAES-CBC-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND256BITAES-CBC-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND128BITAES-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND192BITAES-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND256BITAES-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes128_cbc, "PBEWITHSHAAND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes192_cbc, "PBEWITHSHAAND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes256_cbc, "PBEWITHSHAAND256BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes128_cbc, "PBEWITHSHA256AND128BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes192_cbc, "PBEWITHSHA256AND192BITAES-CBC-BC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory", BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes256_cbc, "PBEWITHSHA256AND256BITAES-CBC-BC");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND192BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND256BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND128BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND192BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND256BITAES-CBC-BC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND128BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND192BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND256BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND128BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND192BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND256BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND128BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND192BITAES-CBC-BC","PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND256BITAES-CBC-BC","PKCS12PBE");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PKCS12PBE");

				addGMacAlgorithm(provider, "AES", PREFIX + "$AESGMAC", PREFIX + "$KeyGen128");
				addPoly1305Algorithm(provider, "AES", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
			}
		}
	}

}