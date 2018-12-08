using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.openssl.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using Integers = org.bouncycastle.util.Integers;

	public class PEMUtilities
	{
		private static readonly Map KEYSIZES = new HashMap();
		private static readonly Set PKCS5_SCHEME_1 = new HashSet();
		private static readonly Set PKCS5_SCHEME_2 = new HashSet();
		private static readonly Map PRFS = new HashMap();
		private static readonly Map PRFS_SALT = new HashMap();

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

			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, "PBKDF2withHMACSHA1");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, "PBKDF2withHMACSHA256");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, "PBKDF2withHMACSHA512");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, "PBKDF2withHMACSHA224");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, "PBKDF2withHMACSHA384");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, "PBKDF2withHMACSHA3-224");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, "PBKDF2withHMACSHA3-256");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, "PBKDF2withHMACSHA3-384");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, "PBKDF2withHMACSHA3-512");
			PRFS.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, "PBKDF2withHMACGOST3411");

			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, Integers.valueOf(20));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, Integers.valueOf(32));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, Integers.valueOf(64));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, Integers.valueOf(28));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, Integers.valueOf(28));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, Integers.valueOf(32));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, Integers.valueOf(64));
			PRFS_SALT.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, Integers.valueOf(32));
		}

		internal static int getKeySize(string algorithm)
		{
			if (!KEYSIZES.containsKey(algorithm))
			{
				throw new IllegalStateException("no key size for algorithm: " + algorithm);
			}

			return ((int?)KEYSIZES.get(algorithm)).Value;
		}

		internal static int getSaltSize(ASN1ObjectIdentifier algorithm)
		{
			if (!PRFS_SALT.containsKey(algorithm))
			{
				throw new IllegalStateException("no salt size for algorithm: " + algorithm);
			}

			return ((int?)PRFS_SALT.get(algorithm)).Value;
		}

		internal static bool isHmacSHA1(AlgorithmIdentifier prf)
		{
			return prf == null || prf.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1);
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

		public static SecretKey generateSecretKeyForPKCS5Scheme2(JcaJceHelper helper, string algorithm, char[] password, byte[] salt, int iterationCount)
		{
			SecretKeyFactory keyGen = helper.createSecretKeyFactory("PBKDF2with8BIT");

			SecretKey sKey = keyGen.generateSecret(new PBEKeySpec(password, salt, iterationCount, PEMUtilities.getKeySize(algorithm)));

			return new SecretKeySpec(sKey.getEncoded(), algorithm);
		}

		public static SecretKey generateSecretKeyForPKCS5Scheme2(JcaJceHelper helper, string algorithm, char[] password, byte[] salt, int iterationCount, AlgorithmIdentifier prf)
		{
			string prfName = (string)PRFS.get(prf.getAlgorithm());
			if (string.ReferenceEquals(prfName, null))
			{
				throw new NoSuchAlgorithmException("unknown PRF in PKCS#2: " + prf.getAlgorithm());
			}

			SecretKeyFactory keyGen = helper.createSecretKeyFactory(prfName);

			SecretKey sKey = keyGen.generateSecret(new PBEKeySpec(password, salt, iterationCount, PEMUtilities.getKeySize(algorithm)));

			return new SecretKeySpec(sKey.getEncoded(), algorithm);
		}

		internal static byte[] crypt(bool encrypt, JcaJceHelper helper, byte[] bytes, char[] password, string dekAlgName, byte[] iv)
		{
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			string alg;
			string blockMode = "CBC";
			string padding = "PKCS5Padding";
			Key sKey;

			// Figure out block mode and padding.
			if (dekAlgName.EndsWith("-CFB", StringComparison.Ordinal))
			{
				blockMode = "CFB";
				padding = "NoPadding";
			}
			if (dekAlgName.EndsWith("-ECB", StringComparison.Ordinal) || "DES-EDE".Equals(dekAlgName) || "DES-EDE3".Equals(dekAlgName))
			{
				// ECB is actually the default (though seldom used) when OpenSSL
				// uses DES-EDE (des2) or DES-EDE3 (des3).
				blockMode = "ECB";
				paramSpec = null;
			}
			if (dekAlgName.EndsWith("-OFB", StringComparison.Ordinal))
			{
				blockMode = "OFB";
				padding = "NoPadding";
			}

			// Figure out algorithm and key size.
			if (dekAlgName.StartsWith("DES-EDE", StringComparison.Ordinal))
			{
				alg = "DESede";
				// "DES-EDE" is actually des2 in OpenSSL-speak!
				// "DES-EDE3" is des3.
				bool des2 = !dekAlgName.StartsWith("DES-EDE3", StringComparison.Ordinal);
				sKey = getKey(helper, password, alg, 24, iv, des2);
			}
			else if (dekAlgName.StartsWith("DES-", StringComparison.Ordinal))
			{
				alg = "DES";
				sKey = getKey(helper, password, alg, 8, iv);
			}
			else if (dekAlgName.StartsWith("BF-", StringComparison.Ordinal))
			{
				alg = "Blowfish";
				sKey = getKey(helper, password, alg, 16, iv);
			}
			else if (dekAlgName.StartsWith("RC2-", StringComparison.Ordinal))
			{
				alg = "RC2";
				int keyBits = 128;
				if (dekAlgName.StartsWith("RC2-40-", StringComparison.Ordinal))
				{
					keyBits = 40;
				}
				else if (dekAlgName.StartsWith("RC2-64-", StringComparison.Ordinal))
				{
					keyBits = 64;
				}
				sKey = getKey(helper, password, alg, keyBits / 8, iv);
				if (paramSpec == null) // ECB block mode
				{
					paramSpec = new RC2ParameterSpec(keyBits);
				}
				else
				{
					paramSpec = new RC2ParameterSpec(keyBits, iv);
				}
			}
			else if (dekAlgName.StartsWith("AES-", StringComparison.Ordinal))
			{
				alg = "AES";
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
					throw new EncryptionException("unknown AES encryption with private key");
				}
				sKey = getKey(helper, password, "AES", keyBits / 8, salt);
			}
			else
			{
				throw new EncryptionException("unknown encryption with private key");
			}

			string transformation = alg + "/" + blockMode + "/" + padding;

			try
			{
				Cipher c = helper.createCipher(transformation);
				int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

				if (paramSpec == null) // ECB block mode
				{
					c.init(mode, sKey);
				}
				else
				{
					c.init(mode, sKey, paramSpec);
				}
				return c.doFinal(bytes);
			}
			catch (Exception e)
			{
				throw new EncryptionException("exception using cipher - please check password and data.", e);
			}
		}

		private static SecretKey getKey(JcaJceHelper helper, char[] password, string algorithm, int keyLength, byte[] salt)
		{
			return getKey(helper, password, algorithm, keyLength, salt, false);
		}

		private static SecretKey getKey(JcaJceHelper helper, char[] password, string algorithm, int keyLength, byte[] salt, bool des2)
		{
			try
			{
				PBEKeySpec spec = new PBEKeySpec(password, salt, 1, keyLength * 8);
				SecretKeyFactory keyFactory = helper.createSecretKeyFactory("PBKDF-OpenSSL");

				byte[] key = keyFactory.generateSecret(spec).getEncoded();

				if (des2 && key.Length >= 24)
				{
					// For DES2, we must copy first 8 bytes into the last 8 bytes.
					JavaSystem.arraycopy(key, 0, key, 16, 8);
				}

				return new SecretKeySpec(key, algorithm);
			}
			catch (GeneralSecurityException e)
			{
				throw new PEMException("Unable to create OpenSSL PBDKF: " + e.Message, e);
			}
		}
	}

}