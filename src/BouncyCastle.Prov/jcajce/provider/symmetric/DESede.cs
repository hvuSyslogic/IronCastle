using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{


	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using DESedeWrapEngine = org.bouncycastle.crypto.engines.DESedeWrapEngine;
	using RFC3211WrapEngine = org.bouncycastle.crypto.engines.RFC3211WrapEngine;
	using DESedeKeyGenerator = org.bouncycastle.crypto.generators.DESedeKeyGenerator;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ISO7816d4Padding = org.bouncycastle.crypto.paddings.ISO7816d4Padding;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class DESede
	{
		private DESede()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new DESedeEngine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new DESedeEngine()), 64)
			{
			}
		}

		/// <summary>
		/// DESede   CFB8
		/// </summary>
		public class DESedeCFB8 : BaseMac
		{
			public DESedeCFB8() : base(new CFBBlockCipherMac(new DESedeEngine()))
			{
			}
		}

		/// <summary>
		/// DESede64
		/// </summary>
		public class DESede64 : BaseMac
		{
			public DESede64() : base(new CBCBlockCipherMac(new DESedeEngine(), 64))
			{
			}
		}

		/// <summary>
		/// DESede64with7816-4Padding
		/// </summary>
		public class DESede64with7816d4 : BaseMac
		{
			public DESede64with7816d4() : base(new CBCBlockCipherMac(new DESedeEngine(), 64, new ISO7816d4Padding()))
			{
			}
		}

		public class CBCMAC : BaseMac
		{
			public CBCMAC() : base(new CBCBlockCipherMac(new DESedeEngine()))
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new DESedeEngine()))
			{
			}
		}

		public class Wrap : BaseWrapCipher
		{
			public Wrap() : base(new DESedeWrapEngine())
			{
			}
		}

		public class RFC3211 : BaseWrapCipher
		{
			public RFC3211() : base(new RFC3211WrapEngine(new DESedeEngine()), 8)
			{
			}
		}

	  /// <summary>
	  /// DESede - the default for this is to generate a key in
	  /// a-b-a format that's 24 bytes long but has 16 bytes of
	  /// key material (the first 8 bytes is repeated as the last
	  /// 8 bytes). If you give it a size, you'll get just what you
	  /// asked for.
	  /// </summary>
		public class KeyGenerator : BaseKeyGenerator
		{
			internal bool keySizeSet = false;

			public KeyGenerator() : base("DESede", 192, new DESedeKeyGenerator())
			{
			}

			public override void engineInit(int keySize, SecureRandom random)
			{
				base.engineInit(keySize, random);
				keySizeSet = true;
			}

			public override SecretKey engineGenerateKey()
			{
				if (uninitialised)
				{
					engine.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), defaultKeySize));
					uninitialised = false;
				}

				//
				// if no key size has been defined generate a 24 byte key in
				// the a-b-a format
				//
				if (!keySizeSet)
				{
					byte[] k = engine.generateKey();

					JavaSystem.arraycopy(k, 0, k, 16, 8);

					return new SecretKeySpec(k, algName);
				}
				else
				{
					return new SecretKeySpec(engine.generateKey(), algName);
				}
			}
		}

		/// <summary>
		/// generate a desEDE key in the a-b-c format.
		/// </summary>
		public class KeyGenerator3 : BaseKeyGenerator
		{
			public KeyGenerator3() : base("DESede3", 192, new DESedeKeyGenerator())
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd3-KeyTripleDES-CBC
		/// </summary>
		public class PBEWithSHAAndDES3Key : BaseBlockCipher
		{
			public PBEWithSHAAndDES3Key() : base(new CBCBlockCipher(new DESedeEngine()), PKCS12, SHA1, 192, 8)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd2-KeyTripleDES-CBC
		/// </summary>
		public class PBEWithSHAAndDES2Key : BaseBlockCipher
		{
			public PBEWithSHAAndDES2Key() : base(new CBCBlockCipher(new DESedeEngine()), PKCS12, SHA1, 128, 8)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd3-KeyTripleDES-CBC
		/// </summary>
		public class PBEWithSHAAndDES3KeyFactory : DES.DESPBEKeyFactory
		{
			public PBEWithSHAAndDES3KeyFactory() : base("PBEwithSHAandDES3Key-CBC", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, true, PKCS12, SHA1, 192, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithSHAAnd2-KeyTripleDES-CBC
		/// </summary>
		public class PBEWithSHAAndDES2KeyFactory : DES.DESPBEKeyFactory
		{
			public PBEWithSHAAndDES2KeyFactory() : base("PBEwithSHAandDES2Key-CBC", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC, true, PKCS12, SHA1, 128, 64)
			{
			}
		}

		public class AlgParamGen : BaseAlgorithmParameterGenerator
		{
			public virtual void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
			{
				throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DES parameter generation.");
			}

			public virtual AlgorithmParameters engineGenerateParameters()
			{
				byte[] iv = new byte[8];

				if (random == null)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}

				random.nextBytes(iv);

				AlgorithmParameters @params;

				try
				{
					@params = createParametersInstance("DES");
					@params.init(new IvParameterSpec(iv));
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.Message);
				}

				return @params;
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("DESede", null)
			{
			}

			public override KeySpec engineGetKeySpec(SecretKey key, Class keySpec)
			{
				if (keySpec == null)
				{
					throw new InvalidKeySpecException("keySpec parameter is null");
				}
				if (key == null)
				{
					throw new InvalidKeySpecException("key parameter is null");
				}

				if (typeof(SecretKeySpec).isAssignableFrom(keySpec))
				{
					return new SecretKeySpec(key.getEncoded(), algName);
				}
				else if (typeof(DESedeKeySpec).isAssignableFrom(keySpec))
				{
					byte[] bytes = key.getEncoded();

					try
					{
						if (bytes.Length == 16)
						{
							byte[] longKey = new byte[24];

							JavaSystem.arraycopy(bytes, 0, longKey, 0, 16);
							JavaSystem.arraycopy(bytes, 0, longKey, 16, 8);

							return new DESedeKeySpec(longKey);
						}
						else
						{
							return new DESedeKeySpec(bytes);
						}
					}
					catch (Exception e)
					{
						throw new InvalidKeySpecException(e.ToString());
					}
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is DESedeKeySpec)
				{
					DESedeKeySpec desKeySpec = (DESedeKeySpec)keySpec;
					return new SecretKeySpec(desKeySpec.getKey(), "DESede");
				}

				return base.engineGenerateSecret(keySpec);
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(DESede).getName();
			internal const string PACKAGE = "org.bouncycastle.jcajce.provider.symmetric"; // JDK 1.2

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("Cipher.DESEDE", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", PKCSObjectIdentifiers_Fields.des_EDE3_CBC, PREFIX + "$CBC");
				provider.addAlgorithm("Cipher.DESEDEWRAP", PREFIX + "$Wrap");
				provider.addAlgorithm("Cipher", PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap, PREFIX + "$Wrap");
				provider.addAlgorithm("Cipher.DESEDERFC3211WRAP", PREFIX + "$RFC3211");
				provider.addAlgorithm("Alg.Alias.Cipher.DESEDERFC3217WRAP", "DESEDEWRAP");

				provider.addAlgorithm("Alg.Alias.Cipher.TDEA", "DESEDE");
				provider.addAlgorithm("Alg.Alias.Cipher.TDEAWRAP", "DESEDEWRAP");
				provider.addAlgorithm("Alg.Alias.KeyGenerator.TDEA", "DESEDE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.TDEA", "DESEDE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.TDEA", "DESEDE");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.TDEA", "DESEDE");

				if (provider.hasAlgorithm("MessageDigest", "SHA-1"))
				{
					provider.addAlgorithm("Cipher.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", PREFIX + "$PBEWithSHAAndDES3Key");
					provider.addAlgorithm("Cipher.BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC", PREFIX + "$BrokePBEWithSHAAndDES3Key");
					provider.addAlgorithm("Cipher.OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC", PREFIX + "$OldPBEWithSHAAndDES3Key");
					provider.addAlgorithm("Cipher.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", PREFIX + "$PBEWithSHAAndDES2Key");
					provider.addAlgorithm("Cipher.BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC", PREFIX + "$BrokePBEWithSHAAndDES2Key");
					provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC, "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1ANDDESEDE", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND3-KEYTRIPLEDES-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND2-KEYTRIPLEDES-CBC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHAAND3-KEYDESEDE-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHAAND2-KEYDESEDE-CBC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND3-KEYDESEDE-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1AND2-KEYDESEDE-CBC", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
					provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1ANDDESEDE-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
				}

				provider.addAlgorithm("KeyGenerator.DESEDE", PREFIX + "$KeyGenerator");
				provider.addAlgorithm("KeyGenerator." + PKCSObjectIdentifiers_Fields.des_EDE3_CBC, PREFIX + "$KeyGenerator3");
				provider.addAlgorithm("KeyGenerator.DESEDEWRAP", PREFIX + "$KeyGenerator");

				provider.addAlgorithm("SecretKeyFactory.DESEDE", PREFIX + "$KeyFactory");

				provider.addAlgorithm("SecretKeyFactory", OIWObjectIdentifiers_Fields.desEDE, PREFIX + "$KeyFactory");

				provider.addAlgorithm("Mac.DESEDECMAC", PREFIX + "$CMAC");
				provider.addAlgorithm("Mac.DESEDEMAC", PREFIX + "$CBCMAC");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDE", "DESEDEMAC");

				provider.addAlgorithm("Mac.DESEDEMAC/CFB8", PREFIX + "$DESedeCFB8");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDE/CFB8", "DESEDEMAC/CFB8");

				provider.addAlgorithm("Mac.DESEDEMAC64", PREFIX + "$DESede64");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDE64", "DESEDEMAC64");

				provider.addAlgorithm("Mac.DESEDEMAC64WITHISO7816-4PADDING", PREFIX + "$DESede64with7816d4");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDE64WITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDEISO9797ALG1MACWITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");
				provider.addAlgorithm("Alg.Alias.Mac.DESEDEISO9797ALG1WITHISO7816-4PADDING", "DESEDEMAC64WITHISO7816-4PADDING");

				provider.addAlgorithm("AlgorithmParameters.DESEDE", PACKAGE + ".util.IvAlgorithmParameters");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESEDE");

				provider.addAlgorithm("AlgorithmParameterGenerator.DESEDE", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESEDE");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", PREFIX + "$PBEWithSHAAndDES3KeyFactory");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", PREFIX + "$PBEWithSHAAndDES2KeyFactory");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDDESEDE", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");

				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES3KEY-CBC", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES2KEY-CBC", "PKCS12PBE");

				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.3", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.4", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWithSHAAnd3KeyTripleDES", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.3", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.4", "PKCS12PBE");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWithSHAAnd3KeyTripleDES", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
			}
		}
	}

}