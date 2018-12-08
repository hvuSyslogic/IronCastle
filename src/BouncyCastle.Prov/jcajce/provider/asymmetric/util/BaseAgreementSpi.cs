using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.misc;
using org.bouncycastle.asn1.gnu;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GNUObjectIdentifiers = org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using DerivationFunction = org.bouncycastle.crypto.DerivationFunction;
	using DHKDFParameters = org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
	using DHKEKGenerator = org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
	using DESParameters = org.bouncycastle.crypto.@params.DESParameters;
	using KDFParameters = org.bouncycastle.crypto.@params.KDFParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Strings = org.bouncycastle.util.Strings;

	public abstract class BaseAgreementSpi : KeyAgreementSpi
	{
		private static readonly Map<string, ASN1ObjectIdentifier> defaultOids = new HashMap<string, ASN1ObjectIdentifier>();
		private static readonly Map<string, int> keySizes = new HashMap<string, int>();
		private static readonly Map<string, string> nameTable = new HashMap<string, string>();

		private static readonly Hashtable oids = new Hashtable();
		private static readonly Hashtable des = new Hashtable();

		static BaseAgreementSpi()
		{
			int? i64 = Integers.valueOf(64);
			int? i128 = Integers.valueOf(128);
			int? i192 = Integers.valueOf(192);
			int? i256 = Integers.valueOf(256);

			keySizes.put("DES", i64);
			keySizes.put("DESEDE", i192);
			keySizes.put("BLOWFISH", i128);
			keySizes.put("AES", i256);

			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_ECB.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_ECB.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_ECB.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CBC.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CBC.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CBC.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CFB.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CFB.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CFB.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_OFB.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_OFB.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_OFB.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_wrap.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_wrap.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_wrap.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CCM.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CCM.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CCM.getId(), i256);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_GCM.getId(), i128);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_GCM.getId(), i192);
			keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_GCM.getId(), i256);
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_wrap.getId(), i128);
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_wrap.getId(), i192);
			keySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_wrap.getId(), i256);
			keySizes.put(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap.getId(), i128);

			keySizes.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId(), i192);
			keySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), i192);
			keySizes.put(OIWObjectIdentifiers_Fields.desCBC.getId(), i64);

			keySizes.put(CryptoProObjectIdentifiers_Fields.gostR28147_gcfb.getId(), i256);
			keySizes.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_None_KeyWrap.getId(), i256);
			keySizes.put(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap.getId(), i256);

			keySizes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1.getId(), Integers.valueOf(160));
			keySizes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256.getId(), i256);
			keySizes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384.getId(), Integers.valueOf(384));
			keySizes.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512.getId(), Integers.valueOf(512));

			defaultOids.put("DESEDE", PKCSObjectIdentifiers_Fields.des_EDE3_CBC);
			defaultOids.put("AES", NISTObjectIdentifiers_Fields.id_aes256_CBC);
			defaultOids.put("CAMELLIA", NTTObjectIdentifiers_Fields.id_camellia256_cbc);
			defaultOids.put("SEED", KISAObjectIdentifiers_Fields.id_seedCBC);
			defaultOids.put("DES", OIWObjectIdentifiers_Fields.desCBC);

			nameTable.put(MiscObjectIdentifiers_Fields.cast5CBC.getId(), "CAST5");
			nameTable.put(MiscObjectIdentifiers_Fields.as_sys_sec_alg_ideaCBC.getId(), "IDEA");
			nameTable.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_ECB.getId(), "Blowfish");
			nameTable.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CBC.getId(), "Blowfish");
			nameTable.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_CFB.getId(), "Blowfish");
			nameTable.put(MiscObjectIdentifiers_Fields.cryptlib_algorithm_blowfish_OFB.getId(), "Blowfish");
			nameTable.put(OIWObjectIdentifiers_Fields.desECB.getId(), "DES");
			nameTable.put(OIWObjectIdentifiers_Fields.desCBC.getId(), "DES");
			nameTable.put(OIWObjectIdentifiers_Fields.desCFB.getId(), "DES");
			nameTable.put(OIWObjectIdentifiers_Fields.desOFB.getId(), "DES");
			nameTable.put(OIWObjectIdentifiers_Fields.desEDE.getId(), "DESede");
			nameTable.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), "DESede");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId(), "DESede");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap.getId(), "RC2");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1.getId(), "HmacSHA1");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224.getId(), "HmacSHA224");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256.getId(), "HmacSHA256");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384.getId(), "HmacSHA384");
			nameTable.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512.getId(), "HmacSHA512");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia128_cbc.getId(), "Camellia");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia192_cbc.getId(), "Camellia");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia256_cbc.getId(), "Camellia");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia128_wrap.getId(), "Camellia");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia192_wrap.getId(), "Camellia");
			nameTable.put(NTTObjectIdentifiers_Fields.id_camellia256_wrap.getId(), "Camellia");
			nameTable.put(KISAObjectIdentifiers_Fields.id_npki_app_cmsSeed_wrap.getId(), "SEED");
			nameTable.put(KISAObjectIdentifiers_Fields.id_seedCBC.getId(), "SEED");
			nameTable.put(KISAObjectIdentifiers_Fields.id_seedMAC.getId(), "SEED");
			nameTable.put(CryptoProObjectIdentifiers_Fields.gostR28147_gcfb.getId(), "GOST28147");

			nameTable.put(NISTObjectIdentifiers_Fields.id_aes128_wrap.getId(), "AES");
			nameTable.put(NISTObjectIdentifiers_Fields.id_aes128_CCM.getId(), "AES");
			nameTable.put(NISTObjectIdentifiers_Fields.id_aes128_CCM.getId(), "AES");

			oids.put("DESEDE", PKCSObjectIdentifiers_Fields.des_EDE3_CBC);
			oids.put("AES", NISTObjectIdentifiers_Fields.id_aes256_CBC);
			oids.put("DES", OIWObjectIdentifiers_Fields.desCBC);

			des.put("DES", "DES");
			des.put("DESEDE", "DES");
			des.put(OIWObjectIdentifiers_Fields.desCBC.getId(), "DES");
			des.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId(), "DES");
			des.put(PKCSObjectIdentifiers_Fields.id_alg_CMS3DESwrap.getId(), "DES");
		}

		protected internal readonly string kaAlgorithm;
		protected internal readonly DerivationFunction kdf;

		protected internal byte[] ukmParameters;

		public BaseAgreementSpi(string kaAlgorithm, DerivationFunction kdf)
		{
			this.kaAlgorithm = kaAlgorithm;
			this.kdf = kdf;
		}

		protected internal static string getAlgorithm(string algDetails)
		{
			if (algDetails.IndexOf('[') > 0)
			{
				return algDetails.Substring(0, algDetails.IndexOf('['));
			}

			if (algDetails.StartsWith(NISTObjectIdentifiers_Fields.aes.getId(), StringComparison.Ordinal))
			{
				return "AES";
			}
			if (algDetails.StartsWith(GNUObjectIdentifiers_Fields.Serpent.getId(), StringComparison.Ordinal))
			{
				return "Serpent";
			}

			string name = (string)nameTable.get(Strings.toUpperCase(algDetails));

			if (!string.ReferenceEquals(name, null))
			{
				return name;
			}

			return algDetails;
		}

		protected internal static int getKeySize(string algDetails)
		{
			if (algDetails.IndexOf('[') > 0)
			{
				return int.Parse(StringHelper.SubstringSpecial(algDetails, algDetails.IndexOf('[') + 1, algDetails.IndexOf(']')));
			}

			string algKey = Strings.toUpperCase(algDetails);
			if (!keySizes.containsKey(algKey))
			{
				return -1;
			}

			return ((int?)keySizes.get(algKey)).Value;
		}

		protected internal static byte[] trimZeroes(byte[] secret)
		{
			if (secret[0] != 0)
			{
				return secret;
			}
			else
			{
				int ind = 0;
				while (ind < secret.Length && secret[ind] == 0)
				{
					ind++;
				}

				byte[] rv = new byte[secret.Length - ind];

				JavaSystem.arraycopy(secret, ind, rv, 0, rv.Length);

				return rv;
			}
		}

		public override byte[] engineGenerateSecret()
		{
			if (kdf != null)
			{
				byte[] secret = calcSecret();
				try
				{
					return getSharedSecretBytes(secret, null, secret.Length * 8);
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new IllegalStateException(e.Message);
				}
			}

			return calcSecret();
		}

		public override int engineGenerateSecret(byte[] sharedSecret, int offset)
		{
			byte[] secret = engineGenerateSecret();

			if (sharedSecret.Length - offset < secret.Length)
			{
				throw new ShortBufferException(kaAlgorithm + " key agreement: need " + secret.Length + " bytes");
			}

			JavaSystem.arraycopy(secret, 0, sharedSecret, offset, secret.Length);

			return secret.Length;
		}

		public override SecretKey engineGenerateSecret(string algorithm)
		{
			string algKey = Strings.toUpperCase(algorithm);
			string oidAlgorithm = algorithm;

			if (oids.containsKey(algKey))
			{
				oidAlgorithm = ((ASN1ObjectIdentifier)oids.get(algKey)).getId();
			}

			int keySize = getKeySize(oidAlgorithm);

			byte[] secret = getSharedSecretBytes(calcSecret(), oidAlgorithm, keySize);

			string algName = getAlgorithm(algorithm);

			if (des.containsKey(algName))
			{
				DESParameters.setOddParity(secret);
			}

			return new SecretKeySpec(secret, algName);
		}

		private byte[] getSharedSecretBytes(byte[] secret, string oidAlgorithm, int keySize)
		{
			if (kdf != null)
			{
				if (keySize < 0)
				{
					throw new NoSuchAlgorithmException("unknown algorithm encountered: " + oidAlgorithm);
				}
				byte[] keyBytes = new byte[keySize / 8];

				if (kdf is DHKEKGenerator)
				{
					if (string.ReferenceEquals(oidAlgorithm, null))
					{
						throw new NoSuchAlgorithmException("algorithm OID is null");
					}
					ASN1ObjectIdentifier oid;
					try
					{
						oid = new ASN1ObjectIdentifier(oidAlgorithm);
					}
					catch (IllegalArgumentException)
					{
						throw new NoSuchAlgorithmException("no OID for algorithm: " + oidAlgorithm);
					}
					DHKDFParameters @params = new DHKDFParameters(oid, keySize, secret, ukmParameters);

					kdf.init(@params);
				}
				else
				{
					KDFParameters @params = new KDFParameters(secret, ukmParameters);

					kdf.init(@params);
				}

				kdf.generateBytes(keyBytes, 0, keyBytes.Length);

				Arrays.clear(secret);

				return keyBytes;
			}
			else
			{
				if (keySize > 0)
				{
					byte[] keyBytes = new byte[keySize / 8];

					JavaSystem.arraycopy(secret, 0, keyBytes, 0, keyBytes.Length);

					Arrays.clear(secret);

					return keyBytes;
				}

				return secret;
			}
		}

		public abstract byte[] calcSecret();
	}

}