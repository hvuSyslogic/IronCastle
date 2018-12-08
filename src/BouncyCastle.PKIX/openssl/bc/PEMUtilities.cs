using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;

using System;

namespace org.bouncycastle.openssl.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using BlowfishEngine = org.bouncycastle.crypto.engines.BlowfishEngine;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using RC2Engine = org.bouncycastle.crypto.engines.RC2Engine;
	using OpenSSLPBEParametersGenerator = org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using OFBBlockCipher = org.bouncycastle.crypto.modes.OFBBlockCipher;
	using BlockCipherPadding = org.bouncycastle.crypto.paddings.BlockCipherPadding;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;
	using Integers = org.bouncycastle.util.Integers;

	public class PEMUtilities
	{
		private static readonly Map KEYSIZES = new HashMap();
		private static readonly Set PKCS5_SCHEME_1 = new HashSet();
		private static readonly Set PKCS5_SCHEME_2 = new HashSet();

		static PEMUtilities()
		{
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD2AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD2AndRC2_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithMD5AndRC2_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC);
			PKCS5_SCHEME_1.add(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndRC2_CBC);

			PKCS5_SCHEME_2.add(PKCSObjectIdentifiers_Fields.id_PBES2);
			PKCS5_SCHEME_2.add(PKCSObjectIdentifiers_Fields.des_EDE3_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes128_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes192_CBC);
			PKCS5_SCHEME_2.add(NISTObjectIdentifiers_Fields.id_aes256_CBC);

			KEYSIZES.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), Integers.valueOf(192));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes128_CBC.getId(), Integers.valueOf(128));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes192_CBC.getId(), Integers.valueOf(192));
			KEYSIZES.put(NISTObjectIdentifiers_Fields.id_aes256_CBC.getId(), Integers.valueOf(256));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4.getId(), Integers.valueOf(128));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4, Integers.valueOf(40));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC, Integers.valueOf(128));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, Integers.valueOf(192));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC2_CBC, Integers.valueOf(128));
			KEYSIZES.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC, Integers.valueOf(40));
		}

		internal static int getKeySize(string algorithm)
		{
			if (!KEYSIZES.containsKey(algorithm))
			{
				throw new IllegalStateException("no key size for algorithm: " + algorithm);
			}

			return ((int?)KEYSIZES.get(algorithm)).Value;
		}

		internal static bool isPKCS5Scheme1(ASN1ObjectIdentifier algOid)
		{
			return PKCS5_SCHEME_1.contains(algOid);
		}

		internal static bool isPKCS5Scheme2(ASN1ObjectIdentifier algOid)
		{
			return PKCS5_SCHEME_2.contains(algOid);
		}

		public static bool isPKCS12(ASN1ObjectIdentifier algOid)
		{
			return algOid.getId().StartsWith(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds.getId(), StringComparison.Ordinal);
		}

		public static KeyParameter generateSecretKeyForPKCS5Scheme2(string algorithm, char[] password, byte[] salt, int iterationCount)
		{
			PBEParametersGenerator paramsGen = new PKCS5S2ParametersGenerator(new SHA1Digest());

			paramsGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iterationCount);

			return (KeyParameter)paramsGen.generateDerivedParameters(PEMUtilities.getKeySize(algorithm));
		}

		internal static byte[] crypt(bool encrypt, byte[] bytes, char[] password, string dekAlgName, byte[] iv)
		{
			byte[] ivValue = iv;
			string blockMode = "CBC";
			BlockCipher engine;
			BlockCipherPadding padding = new PKCS7Padding();
			KeyParameter sKey;

			// Figure out block mode and padding.
			if (dekAlgName.EndsWith("-CFB", StringComparison.Ordinal))
			{
				blockMode = "CFB";
				padding = null;
			}
			if (dekAlgName.EndsWith("-ECB", StringComparison.Ordinal) || "DES-EDE".Equals(dekAlgName) || "DES-EDE3".Equals(dekAlgName))
			{
				// ECB is actually the default (though seldom used) when OpenSSL
				// uses DES-EDE (des2) or DES-EDE3 (des3).
				blockMode = "ECB";
				ivValue = null;
			}
			if (dekAlgName.EndsWith("-OFB", StringComparison.Ordinal))
			{
				blockMode = "OFB";
				padding = null;
			}

			// Figure out algorithm and key size.
			if (dekAlgName.StartsWith("DES-EDE", StringComparison.Ordinal))
			{
				// "DES-EDE" is actually des2 in OpenSSL-speak!
				// "DES-EDE3" is des3.
				bool des2 = !dekAlgName.StartsWith("DES-EDE3", StringComparison.Ordinal);
				sKey = getKey(password, 24, iv, des2);
				engine = new DESedeEngine();
			}
			else if (dekAlgName.StartsWith("DES-", StringComparison.Ordinal))
			{
				sKey = getKey(password, 8, iv);
				engine = new DESEngine();
			}
			else if (dekAlgName.StartsWith("BF-", StringComparison.Ordinal))
			{
				sKey = getKey(password, 16, iv);
				engine = new BlowfishEngine();
			}
			else if (dekAlgName.StartsWith("RC2-", StringComparison.Ordinal))
			{
				int keyBits = 128;
				if (dekAlgName.StartsWith("RC2-40-", StringComparison.Ordinal))
				{
					keyBits = 40;
				}
				else if (dekAlgName.StartsWith("RC2-64-", StringComparison.Ordinal))
				{
					keyBits = 64;
				}
				sKey = new RC2Parameters(getKey(password, keyBits / 8, iv).getKey(), keyBits);
				engine = new RC2Engine();
			}
			else if (dekAlgName.StartsWith("AES-", StringComparison.Ordinal))
			{
				byte[] salt = iv;
				if (salt.Length > 8)
				{
					salt = new byte[8];
					JavaSystem.arraycopy(iv, 0, salt, 0, 8);
				}

				int keyBits;
				if (dekAlgName.StartsWith("AES-128-", StringComparison.Ordinal))
				{
					keyBits = 128;
				}
				else if (dekAlgName.StartsWith("AES-192-", StringComparison.Ordinal))
				{
					keyBits = 192;
				}
				else if (dekAlgName.StartsWith("AES-256-", StringComparison.Ordinal))
				{
					keyBits = 256;
				}
				else
				{
					throw new EncryptionException("unknown AES encryption with private key: " + dekAlgName);
				}
				sKey = getKey(password, keyBits / 8, salt);
				engine = new AESEngine();
			}
			else
			{
				throw new EncryptionException("unknown encryption with private key: " + dekAlgName);
			}

			if (blockMode.Equals("CBC"))
			{
				engine = new CBCBlockCipher(engine);
			}
			else if (blockMode.Equals("CFB"))
			{
				engine = new CFBBlockCipher(engine, engine.getBlockSize() * 8);
			}
			else if (blockMode.Equals("OFB"))
			{
				engine = new OFBBlockCipher(engine, engine.getBlockSize() * 8);
			}

			try
			{
				BufferedBlockCipher c;
				if (padding == null)
				{
					c = new BufferedBlockCipher(engine);
				}
				else
				{
					c = new PaddedBufferedBlockCipher(engine, padding);
				}

				if (ivValue == null) // ECB block mode
				{
					c.init(encrypt, sKey);
				}
				else
				{
					c.init(encrypt, new ParametersWithIV(sKey, ivValue));
				}

				byte[] @out = new byte[c.getOutputSize(bytes.Length)];

				int procLen = c.processBytes(bytes, 0, bytes.Length, @out, 0);

				procLen += c.doFinal(@out, procLen);

				if (procLen == @out.Length)
				{
					return @out;
				}
				else
				{
					byte[] rv = new byte[procLen];

					JavaSystem.arraycopy(@out, 0, rv, 0, procLen);

					return rv;
				}
			}
			catch (Exception e)
			{
				throw new EncryptionException("exception using cipher - please check password and data.", e);
			}
		}

		private static KeyParameter getKey(char[] password, int keyLength, byte[] salt)
		{
			return getKey(password, keyLength, salt, false);
		}

		private static KeyParameter getKey(char[] password, int keyLength, byte[] salt, bool des2)
		{
			PBEParametersGenerator paramsGen = new OpenSSLPBEParametersGenerator();

			paramsGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, 1);

			KeyParameter kp = (KeyParameter)paramsGen.generateDerivedParameters(keyLength * 8);

			if (des2 && kp.getKey().Length == 24)
			{
				// For DES2, we must copy first 8 bytes into the last 8 bytes.
				byte[] key = kp.getKey();

				JavaSystem.arraycopy(key, 0, key, 16, 8);

				return new KeyParameter(key);
			}

			return kp;
		}
	}

}