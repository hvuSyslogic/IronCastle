using org.bouncycastle.jcajce.provider.symmetric.util;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using PasswordConverter = org.bouncycastle.crypto.PasswordConverter;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using RFC3211WrapEngine = org.bouncycastle.crypto.engines.RFC3211WrapEngine;
	using DESKeyGenerator = org.bouncycastle.crypto.generators.DESKeyGenerator;
	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using CFBBlockCipherMac = org.bouncycastle.crypto.macs.CFBBlockCipherMac;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using ISO9797Alg3Mac = org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using ISO7816d4Padding = org.bouncycastle.crypto.paddings.ISO7816d4Padding;
	using DESParameters = org.bouncycastle.crypto.@params.DESParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BCPBEKey = org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
	using BaseAlgorithmParameterGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
	using BaseBlockCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
	using BaseKeyGenerator = org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
	using BaseMac = org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using BaseWrapCipher = org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
	using PBE = org.bouncycastle.jcajce.provider.symmetric.util.PBE;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

	public sealed class DES
	{
		private DES()
		{
		}

		public class ECB : BaseBlockCipher
		{
			public ECB() : base(new DESEngine())
			{
			}
		}

		public class CBC : BaseBlockCipher
		{
			public CBC() : base(new CBCBlockCipher(new DESEngine()), 64)
			{
			}
		}

		/// <summary>
		/// DES   CFB8
		/// </summary>
		public class DESCFB8 : BaseMac
		{
			public DESCFB8() : base(new CFBBlockCipherMac(new DESEngine()))
			{
			}
		}

		/// <summary>
		/// DES64
		/// </summary>
		public class DES64 : BaseMac
		{
			public DES64() : base(new CBCBlockCipherMac(new DESEngine(), 64))
			{
			}
		}

		/// <summary>
		/// DES64with7816-4Padding
		/// </summary>
		public class DES64with7816d4 : BaseMac
		{
			public DES64with7816d4() : base(new CBCBlockCipherMac(new DESEngine(), 64, new ISO7816d4Padding()))
			{
			}
		}

		public class CBCMAC : BaseMac
		{
			public CBCMAC() : base(new CBCBlockCipherMac(new DESEngine()))
			{
			}
		}

		public class CMAC : BaseMac
		{
			public CMAC() : base(new CMac(new DESEngine()))
			{
			}
		}

		/// <summary>
		/// DES9797Alg3with7816-4Padding
		/// </summary>
		public class DES9797Alg3with7816d4 : BaseMac
		{
			public DES9797Alg3with7816d4() : base(new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding()))
			{
			}
		}

		/// <summary>
		/// DES9797Alg3
		/// </summary>
		public class DES9797Alg3 : BaseMac
		{
			public DES9797Alg3() : base(new ISO9797Alg3Mac(new DESEngine()))
			{
			}
		}

		public class RFC3211 : BaseWrapCipher
		{
			public RFC3211() : base(new RFC3211WrapEngine(new DESEngine()), 8)
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

	  /// <summary>
	  /// DES - the default for this is to generate a key in
	  /// a-b-a format that's 24 bytes long but has 16 bytes of
	  /// key material (the first 8 bytes is repeated as the last
	  /// 8 bytes). If you give it a size, you'll get just what you
	  /// asked for.
	  /// </summary>
		public class KeyGenerator : BaseKeyGenerator
		{
			public KeyGenerator() : base("DES", 64, new DESKeyGenerator())
			{
			}

			public override void engineInit(int keySize, SecureRandom random)
			{
				base.engineInit(keySize, random);
			}

			public override SecretKey engineGenerateKey()
			{
				if (uninitialised)
				{
					engine.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), defaultKeySize));
					uninitialised = false;
				}

				return new SecretKeySpec(engine.generateKey(), algName);
			}
		}

		public class KeyFactory : BaseSecretKeyFactory
		{
			public KeyFactory() : base("DES", null)
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
				else if (typeof(DESKeySpec).isAssignableFrom(keySpec))
				{
					byte[] bytes = key.getEncoded();

					try
					{
						return new DESKeySpec(bytes);
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
				if (keySpec is DESKeySpec)
				{
					DESKeySpec desKeySpec = (DESKeySpec)keySpec;
					return new SecretKeySpec(desKeySpec.getKey(), "DES");
				}

				return base.engineGenerateSecret(keySpec);
			}
		}

		public class DESPBEKeyFactory : BaseSecretKeyFactory
		{
			internal bool forCipher;
			internal int scheme;
			internal int digest;
			internal int keySize;
			internal int ivSize;

			public DESPBEKeyFactory(string algorithm, ASN1ObjectIdentifier oid, bool forCipher, int scheme, int digest, int keySize, int ivSize) : base(algorithm, oid)
			{

				this.forCipher = forCipher;
				this.scheme = scheme;
				this.digest = digest;
				this.keySize = keySize;
				this.ivSize = ivSize;
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is PBEKeySpec)
				{
					PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;
					CipherParameters param;

					if (pbeSpec.getSalt() == null)
					{
						if (scheme == PKCS5S1 || scheme == PKCS5S1_UTF8)
						{
							return new PBKDF1Key(pbeSpec.getPassword(), scheme == PKCS5S1 ? PasswordConverter.ASCII : PasswordConverter.UTF8);
						}
						else
						{
							return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, null);
						}
					}

					if (forCipher)
					{
						param = PBE_Util.makePBEParameters(pbeSpec, scheme, digest, keySize, ivSize);
					}
					else
					{
						param = PBE_Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);
					}

					KeyParameter kParam;
					if (param is ParametersWithIV)
					{
						kParam = (KeyParameter)((ParametersWithIV)param).getParameters();
					}
					else
					{
						kParam = (KeyParameter)param;
					}

					DESParameters.setOddParity(kParam.getKey());

					return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}
		}

		/// <summary>
		/// PBEWithMD2AndDES
		/// </summary>
		public class PBEWithMD2KeyFactory : DESPBEKeyFactory
		{
			public PBEWithMD2KeyFactory() : base("PBEwithMD2andDES", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC, true, PKCS5S1, MD2, 64, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithMD5AndDES
		/// </summary>
		public class PBEWithMD5KeyFactory : DESPBEKeyFactory
		{
			public PBEWithMD5KeyFactory() : base("PBEwithMD5andDES", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC, true, PKCS5S1, MD5, 64, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1AndDES
		/// </summary>
		public class PBEWithSHA1KeyFactory : DESPBEKeyFactory
		{
			public PBEWithSHA1KeyFactory() : base("PBEwithSHA1andDES", org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC, true, PKCS5S1, SHA1, 64, 64)
			{
			}
		}

		/// <summary>
		/// PBEWithMD2AndDES
		/// </summary>
		public class PBEWithMD2 : BaseBlockCipher
		{
			public PBEWithMD2() : base(new CBCBlockCipher(new DESEngine()), PKCS5S1, MD2, 64, 8)
			{
			}
		}

		/// <summary>
		/// PBEWithMD5AndDES
		/// </summary>
		public class PBEWithMD5 : BaseBlockCipher
		{
			public PBEWithMD5() : base(new CBCBlockCipher(new DESEngine()), PKCS5S1, MD5, 64, 8)
			{
			}
		}

		/// <summary>
		/// PBEWithSHA1AndDES
		/// </summary>
		public class PBEWithSHA1 : BaseBlockCipher
		{
			public PBEWithSHA1() : base(new CBCBlockCipher(new DESEngine()), PKCS5S1, SHA1, 64, 8)
			{
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(DES).getName();
			internal const string PACKAGE = "org.bouncycastle.jcajce.provider.symmetric"; // JDK 1.2

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{

				provider.addAlgorithm("Cipher.DES", PREFIX + "$ECB");
				provider.addAlgorithm("Cipher", OIWObjectIdentifiers_Fields.desCBC, PREFIX + "$CBC");

				addAlias(provider, OIWObjectIdentifiers_Fields.desCBC, "DES");

				provider.addAlgorithm("Cipher.DESRFC3211WRAP", PREFIX + "$RFC3211");

				provider.addAlgorithm("KeyGenerator.DES", PREFIX + "$KeyGenerator");

				provider.addAlgorithm("SecretKeyFactory.DES", PREFIX + "$KeyFactory");

				provider.addAlgorithm("Mac.DESCMAC", PREFIX + "$CMAC");
				provider.addAlgorithm("Mac.DESMAC", PREFIX + "$CBCMAC");
				provider.addAlgorithm("Alg.Alias.Mac.DES", "DESMAC");

				provider.addAlgorithm("Mac.DESMAC/CFB8", PREFIX + "$DESCFB8");
				provider.addAlgorithm("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");

				provider.addAlgorithm("Mac.DESMAC64", PREFIX + "$DES64");
				provider.addAlgorithm("Alg.Alias.Mac.DES64", "DESMAC64");

				provider.addAlgorithm("Mac.DESMAC64WITHISO7816-4PADDING", PREFIX + "$DES64with7816d4");
				provider.addAlgorithm("Alg.Alias.Mac.DES64WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
				provider.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1MACWITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
				provider.addAlgorithm("Alg.Alias.Mac.DESISO9797ALG1WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");

				provider.addAlgorithm("Mac.DESWITHISO9797", PREFIX + "$DES9797Alg3");
				provider.addAlgorithm("Alg.Alias.Mac.DESISO9797MAC", "DESWITHISO9797");

				provider.addAlgorithm("Mac.ISO9797ALG3MAC", PREFIX + "$DES9797Alg3");
				provider.addAlgorithm("Alg.Alias.Mac.ISO9797ALG3", "ISO9797ALG3MAC");
				provider.addAlgorithm("Mac.ISO9797ALG3WITHISO7816-4PADDING", PREFIX + "$DES9797Alg3with7816d4");
				provider.addAlgorithm("Alg.Alias.Mac.ISO9797ALG3MACWITHISO7816-4PADDING", "ISO9797ALG3WITHISO7816-4PADDING");

				provider.addAlgorithm("AlgorithmParameters.DES", PACKAGE + ".util.IvAlgorithmParameters");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameters", OIWObjectIdentifiers_Fields.desCBC, "DES");

				provider.addAlgorithm("AlgorithmParameterGenerator.DES", PREFIX + "$AlgParamGen");
				provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + OIWObjectIdentifiers_Fields.desCBC, "DES");

				provider.addAlgorithm("Cipher.PBEWITHMD2ANDDES", PREFIX + "$PBEWithMD2");
				provider.addAlgorithm("Cipher.PBEWITHMD5ANDDES", PREFIX + "$PBEWithMD5");
				provider.addAlgorithm("Cipher.PBEWITHSHA1ANDDES", PREFIX + "$PBEWithSHA1");

				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
				provider.addAlgorithm("Alg.Alias.Cipher", PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");

				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHMD2ANDDES-CBC", "PBEWITHMD2ANDDES");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHMD5ANDDES-CBC", "PBEWITHMD5ANDDES");
				provider.addAlgorithm("Alg.Alias.Cipher.PBEWITHSHA1ANDDES-CBC", "PBEWITHSHA1ANDDES");

				provider.addAlgorithm("SecretKeyFactory.PBEWITHMD2ANDDES", PREFIX + "$PBEWithMD2KeyFactory");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHMD5ANDDES", PREFIX + "$PBEWithMD5KeyFactory");
				provider.addAlgorithm("SecretKeyFactory.PBEWITHSHA1ANDDES", PREFIX + "$PBEWithSHA1KeyFactory");

				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHMD2ANDDES-CBC", "PBEWITHMD2ANDDES");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHMD5ANDDES-CBC", "PBEWITHMD5ANDDES");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDDES-CBC", "PBEWITHSHA1ANDDES");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
				provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
			}

			public virtual void addAlias(ConfigurableProvider provider, ASN1ObjectIdentifier oid, string name)
			{
				provider.addAlgorithm("Alg.Alias.KeyGenerator." + oid.getId(), name);
				provider.addAlgorithm("Alg.Alias.KeyFactory." + oid.getId(), name);
			}
		}
	}

}