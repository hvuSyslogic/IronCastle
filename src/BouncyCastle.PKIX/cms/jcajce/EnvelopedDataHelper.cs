using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.cms;

using System;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RC2CBCParameter = org.bouncycastle.asn1.pkcs.RC2CBCParameter;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;
	using SymmetricKeyUnwrapper = org.bouncycastle.@operator.SymmetricKeyUnwrapper;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceKTSKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyUnwrapper;

	public class EnvelopedDataHelper
	{
		protected internal static readonly SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

		protected internal static readonly Map BASE_CIPHER_NAMES = new HashMap();
		protected internal static readonly Map CIPHER_ALG_NAMES = new HashMap();
		protected internal static readonly Map MAC_ALG_NAMES = new HashMap();

		private static readonly Map PBKDF2_ALG_NAMES = new HashMap();

		static EnvelopedDataHelper()
		{
			BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_CBC, "DES");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC, "AES");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC, "AES");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC, "AES");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.CAST5_CBC, "CAST5");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA128_CBC, "Camellia");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA192_CBC, "Camellia");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.CAMELLIA256_CBC, "Camellia");
			BASE_CIPHER_NAMES.put(CMSAlgorithm.SEED_CBC, "SEED");
			BASE_CIPHER_NAMES.put(PKCSObjectIdentifiers_Fields.rc4, "RC4");
			BASE_CIPHER_NAMES.put(CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, "GOST28147");

			CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_CBC, "DES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA/ECB/PKCS1Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.CAST5_CBC, "CAST5/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA128_CBC, "Camellia/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA192_CBC, "Camellia/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.CAMELLIA256_CBC, "Camellia/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.SEED_CBC, "SEED/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.rc4, "RC4");

			MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDEMac");
			MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AESMac");
			MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AESMac");
			MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AESMac");
			MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2Mac");

			PBKDF2_ALG_NAMES.put(PasswordRecipient_PRF.HMacSHA1.getAlgorithmID(), "PBKDF2WITHHMACSHA1");
			PBKDF2_ALG_NAMES.put(PasswordRecipient_PRF.HMacSHA224.getAlgorithmID(), "PBKDF2WITHHMACSHA224");
			PBKDF2_ALG_NAMES.put(PasswordRecipient_PRF.HMacSHA256.getAlgorithmID(), "PBKDF2WITHHMACSHA256");
			PBKDF2_ALG_NAMES.put(PasswordRecipient_PRF.HMacSHA384.getAlgorithmID(), "PBKDF2WITHHMACSHA384");
			PBKDF2_ALG_NAMES.put(PasswordRecipient_PRF.HMacSHA512.getAlgorithmID(), "PBKDF2WITHHMACSHA512");
		}

		private static readonly short[] rc2Table = new short[] {0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36, 0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa, 0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf, 0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6, 0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2, 0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f, 0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab};

		private static readonly short[] rc2Ekb = new short[] {0x5d, 0xbe, 0x9b, 0x8b, 0x11, 0x99, 0x6e, 0x4d, 0x59, 0xf3, 0x85, 0xa6, 0x3f, 0xb7, 0x83, 0xc5, 0xe4, 0x73, 0x6b, 0x3a, 0x68, 0x5a, 0xc0, 0x47, 0xa0, 0x64, 0x34, 0x0c, 0xf1, 0xd0, 0x52, 0xa5, 0xb9, 0x1e, 0x96, 0x43, 0x41, 0xd8, 0xd4, 0x2c, 0xdb, 0xf8, 0x07, 0x77, 0x2a, 0xca, 0xeb, 0xef, 0x10, 0x1c, 0x16, 0x0d, 0x38, 0x72, 0x2f, 0x89, 0xc1, 0xf9, 0x80, 0xc4, 0x6d, 0xae, 0x30, 0x3d, 0xce, 0x20, 0x63, 0xfe, 0xe6, 0x1a, 0xc7, 0xb8, 0x50, 0xe8, 0x24, 0x17, 0xfc, 0x25, 0x6f, 0xbb, 0x6a, 0xa3, 0x44, 0x53, 0xd9, 0xa2, 0x01, 0xab, 0xbc, 0xb6, 0x1f, 0x98, 0xee, 0x9a, 0xa7, 0x2d, 0x4f, 0x9e, 0x8e, 0xac, 0xe0, 0xc6, 0x49, 0x46, 0x29, 0xf4, 0x94, 0x8a, 0xaf, 0xe1, 0x5b, 0xc3, 0xb3, 0x7b, 0x57, 0xd1, 0x7c, 0x9c, 0xed, 0x87, 0x40, 0x8c, 0xe2, 0xcb, 0x93, 0x14, 0xc9, 0x61, 0x2e, 0xe5, 0xcc, 0xf6, 0x5e, 0xa8, 0x5c, 0xd6, 0x75, 0x8d, 0x62, 0x95, 0x58, 0x69, 0x76, 0xa1, 0x4a, 0xb5, 0x55, 0x09, 0x78, 0x33, 0x82, 0xd7, 0xdd, 0x79, 0xf5, 0x1b, 0x0b, 0xde, 0x26, 0x21, 0x28, 0x74, 0x04, 0x97, 0x56, 0xdf, 0x3c, 0xf0, 0x37, 0x39, 0xdc, 0xff, 0x06, 0xa4, 0xea, 0x42, 0x08, 0xda, 0xb4, 0x71, 0xb0, 0xcf, 0x12, 0x7a, 0x4e, 0xfa, 0x6c, 0x1d, 0x84, 0x00, 0xc8, 0x7f, 0x91, 0x45, 0xaa, 0x2b, 0xc2, 0xb1, 0x8f, 0xd5, 0xba, 0xf2, 0xad, 0x19, 0xb2, 0x67, 0x36, 0xf7, 0x0f, 0x0a, 0x92, 0x7d, 0xe3, 0x9d, 0xe9, 0x90, 0x3e, 0x23, 0x27, 0x66, 0x13, 0xec, 0x81, 0x15, 0xbd, 0x22, 0xbf, 0x9f, 0x7e, 0xa9, 0x51, 0x4b, 0x4c, 0xfb, 0x02, 0xd3, 0x70, 0x86, 0x31, 0xe7, 0x3b, 0x05, 0x03, 0x54, 0x60, 0x48, 0x65, 0x18, 0xd2, 0xcd, 0x5f, 0x32, 0x88, 0x0e, 0x35, 0xfd};

		private JcaJceExtHelper helper;

		public EnvelopedDataHelper(JcaJceExtHelper helper)
		{
			this.helper = helper;
		}

		public virtual string getBaseCipherName(ASN1ObjectIdentifier algorithm)
		{
			string name = (string)BASE_CIPHER_NAMES.get(algorithm);

			if (string.ReferenceEquals(name, null))
			{
				return algorithm.getId();
			}

			return name;
		}

		public virtual Key getJceKey(GenericKey key)
		{
			if (key.getRepresentation() is Key)
			{
				return (Key)key.getRepresentation();
			}

			if (key.getRepresentation() is byte[])
			{
				return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
			}

			throw new IllegalArgumentException("unknown generic key type");
		}

		public virtual Key getJceKey(ASN1ObjectIdentifier algorithm, GenericKey key)
		{
			if (key.getRepresentation() is Key)
			{
				return (Key)key.getRepresentation();
			}

			if (key.getRepresentation() is byte[])
			{
				return new SecretKeySpec((byte[])key.getRepresentation(), getBaseCipherName(algorithm));
			}

			throw new IllegalArgumentException("unknown generic key type");
		}

		public virtual void keySizeCheck(AlgorithmIdentifier keyAlgorithm, Key key)
		{
			int expectedKeySize = EnvelopedDataHelper.KEY_SIZE_PROVIDER.getKeySize(keyAlgorithm);
			if (expectedKeySize > 0)
			{
				byte[] keyEnc = null;

				try
				{
					keyEnc = key.getEncoded();
				}
				catch (Exception)
				{
					// ignore - we're using a HSM...
				}

				if (keyEnc != null)
				{
					if (keyEnc.Length * 8 != expectedKeySize)
					{
						throw new CMSException("Expected key size for algorithm OID not found in recipient.");
					}
				}
			}
		}

		public virtual Cipher createCipher(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string cipherName = (string)CIPHER_ALG_NAMES.get(algorithm);

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createCipher(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createCipher(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual Mac createMac(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string macName = (string)MAC_ALG_NAMES.get(algorithm);

				if (!string.ReferenceEquals(macName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createMac(macName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createMac(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create mac: " + e.Message, e);
			}
		}

		public virtual Cipher createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
		{
			string cipherName = (string)BASE_CIPHER_NAMES.get(algorithm);

			if (string.ReferenceEquals(cipherName, null))
			{
				throw new CMSException("no name for " + algorithm);
			}

			cipherName += "RFC3211Wrap";

			try
			{
				 return helper.createCipher(cipherName);
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual KeyAgreement createKeyAgreement(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string agreementName = (string)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(agreementName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyAgreement(agreementName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyAgreement(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create key agreement: " + e.Message, e);
			}
		}

		public virtual AlgorithmParameterGenerator createAlgorithmParameterGenerator(ASN1ObjectIdentifier algorithm)
		{
			string algorithmName = (string)BASE_CIPHER_NAMES.get(algorithm);

			if (!string.ReferenceEquals(algorithmName, null))
			{
				try
				{
					// this is reversed as the Sun policy files now allow unlimited strength RSA
					return helper.createAlgorithmParameterGenerator(algorithmName);
				}
				catch (NoSuchAlgorithmException)
				{
					// Ignore
				}
			}
			return helper.createAlgorithmParameterGenerator(algorithm.getId());
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public javax.crypto.Cipher createContentCipher(final java.security.Key sKey, final org.bouncycastle.asn1.x509.AlgorithmIdentifier encryptionAlgID) throws org.bouncycastle.cms.CMSException
		public virtual Cipher createContentCipher(Key sKey, AlgorithmIdentifier encryptionAlgID)
		{
			return (Cipher)execute(new JCECallbackAnonymousInnerClass(this, sKey, encryptionAlgID));
		}

		public class JCECallbackAnonymousInnerClass : JCECallback
		{
			private readonly EnvelopedDataHelper outerInstance;

			private Key sKey;
			private AlgorithmIdentifier encryptionAlgID;

			public JCECallbackAnonymousInnerClass(EnvelopedDataHelper outerInstance, Key sKey, AlgorithmIdentifier encryptionAlgID)
			{
				this.outerInstance = outerInstance;
				this.sKey = sKey;
				this.encryptionAlgID = encryptionAlgID;
			}

			public object doInJCE()
			{
				Cipher cipher = outerInstance.createCipher(encryptionAlgID.getAlgorithm());
				ASN1Encodable sParams = encryptionAlgID.getParameters();
				string encAlg = encryptionAlgID.getAlgorithm().getId();

				if (sParams != null && !(sParams is ASN1Null))
				{
					try
					{
						AlgorithmParameters @params = outerInstance.createAlgorithmParameters(encryptionAlgID.getAlgorithm());

						CMSUtils.loadParameters(@params, sParams);

						cipher.init(Cipher.DECRYPT_MODE, sKey, @params);
					}
					catch (NoSuchAlgorithmException e)
					{
						if (encAlg.Equals(CMSAlgorithm.DES_CBC.getId()) || encAlg.Equals(CMSEnvelopedDataGenerator.DES_EDE3_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.IDEA_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.AES128_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.AES192_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.AES256_CBC))
						{
							cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(ASN1OctetString.getInstance(sParams).getOctets()));
						}
						else
						{
							throw e;
						}
					}
				}
				else
				{
					if (encAlg.Equals(CMSAlgorithm.DES_CBC.getId()) || encAlg.Equals(CMSEnvelopedDataGenerator.DES_EDE3_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.IDEA_CBC) || encAlg.Equals(CMSEnvelopedDataGenerator.CAST5_CBC))
					{
						cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(new byte[8]));
					}
					else
					{
						cipher.init(Cipher.DECRYPT_MODE, sKey);
					}
				}

				return cipher;
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: javax.crypto.Mac createContentMac(final java.security.Key sKey, final org.bouncycastle.asn1.x509.AlgorithmIdentifier macAlgId) throws org.bouncycastle.cms.CMSException
		public virtual Mac createContentMac(Key sKey, AlgorithmIdentifier macAlgId)
		{
			return (Mac)execute(new JCECallbackAnonymousInnerClass2(this, sKey, macAlgId));
		}

		public class JCECallbackAnonymousInnerClass2 : JCECallback
		{
			private readonly EnvelopedDataHelper outerInstance;

			private Key sKey;
			private AlgorithmIdentifier macAlgId;

			public JCECallbackAnonymousInnerClass2(EnvelopedDataHelper outerInstance, Key sKey, AlgorithmIdentifier macAlgId)
			{
				this.outerInstance = outerInstance;
				this.sKey = sKey;
				this.macAlgId = macAlgId;
			}

			public object doInJCE()
			{
				Mac mac = outerInstance.createMac(macAlgId.getAlgorithm());
				ASN1Encodable sParams = macAlgId.getParameters();
				string macAlg = macAlgId.getAlgorithm().getId();

				if (sParams != null && !(sParams is ASN1Null))
				{
					try
					{
						AlgorithmParameters @params = outerInstance.createAlgorithmParameters(macAlgId.getAlgorithm());

						CMSUtils.loadParameters(@params, sParams);

						mac.init(sKey, @params.getParameterSpec(typeof(AlgorithmParameterSpec)));
					}
					catch (NoSuchAlgorithmException e)
					{
						throw e;
					}
				}
				else
				{
					mac.init(sKey);
				}

				return mac;
			}
		}

		public virtual AlgorithmParameters createAlgorithmParameters(ASN1ObjectIdentifier algorithm)
		{
			string algorithmName = (string)BASE_CIPHER_NAMES.get(algorithm);

			if (!string.ReferenceEquals(algorithmName, null))
			{
				try
				{
					// this is reversed as the Sun policy files now allow unlimited strength RSA
					return helper.createAlgorithmParameters(algorithmName);
				}
				catch (NoSuchAlgorithmException)
				{
					// Ignore
				}
			}
			return helper.createAlgorithmParameters(algorithm.getId());
		}


		public virtual KeyPairGenerator createKeyPairGenerator(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string cipherName = (string)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyPairGenerator(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyPairGenerator(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create key pair generator: " + e.Message, e);
			}
		}

		public virtual KeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string cipherName = (string)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyGenerator(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyGenerator(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create key generator: " + e.Message, e);
			}
		}

		public virtual AlgorithmParameters generateParameters(ASN1ObjectIdentifier encryptionOID, SecretKey encKey, SecureRandom rand)
		{
			try
			{
				AlgorithmParameterGenerator pGen = createAlgorithmParameterGenerator(encryptionOID);

				if (encryptionOID.Equals(CMSAlgorithm.RC2_CBC))
				{
					byte[] iv = new byte[8];

					rand.nextBytes(iv);

					try
					{
						pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv), rand);
					}
					catch (InvalidAlgorithmParameterException e)
					{
						throw new CMSException("parameters generation error: " + e, e);
					}
				}

				return pGen.generateParameters();
			}
			catch (NoSuchAlgorithmException)
			{
				return null;
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("exception creating algorithm parameter generator: " + e, e);
			}
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier encryptionOID, AlgorithmParameters @params)
		{
			ASN1Encodable asn1Params;
			if (@params != null)
			{
				asn1Params = CMSUtils.extractParameters(@params);
			}
			else
			{
				asn1Params = DERNull.INSTANCE;
			}

			return new AlgorithmIdentifier(encryptionOID, asn1Params);
		}

		internal static object execute(JCECallback callback)
		{
			try
			{
				return callback.doInJCE();
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new CMSException("can't find algorithm.", e);
			}
			catch (InvalidKeyException e)
			{
				throw new CMSException("key invalid in message.", e);
			}
			catch (NoSuchProviderException e)
			{
				throw new CMSException("can't find provider.", e);
			}
			catch (NoSuchPaddingException e)
			{
				throw new CMSException("required padding not supported.", e);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new CMSException("algorithm parameters invalid.", e);
			}
			catch (InvalidParameterSpecException e)
			{
				throw new CMSException("MAC algorithm parameter spec invalid.", e);
			}
		}

		public virtual KeyFactory createKeyFactory(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string cipherName = (string)BASE_CIPHER_NAMES.get(algorithm);

				if (!string.ReferenceEquals(cipherName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyFactory(cipherName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createKeyFactory(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CMSException("cannot create key factory: " + e.Message, e);
			}
		}

		public virtual JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
		{
			return helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
		}

		public virtual JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
		{
			return helper.createAsymmetricUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo);
		}

		public virtual SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
		{
			return helper.createSymmetricUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier macOID, AlgorithmParameterSpec paramSpec)
		{
			if (paramSpec is IvParameterSpec)
			{
				return new AlgorithmIdentifier(macOID, new DEROctetString(((IvParameterSpec)paramSpec).getIV()));
			}

			if (paramSpec is RC2ParameterSpec)
			{
				RC2ParameterSpec rc2Spec = (RC2ParameterSpec)paramSpec;

				int effKeyBits = ((RC2ParameterSpec)paramSpec).getEffectiveKeyBits();

				if (effKeyBits != -1)
				{
					int parameterVersion;

					if (effKeyBits < 256)
					{
						parameterVersion = rc2Table[effKeyBits];
					}
					else
					{
						parameterVersion = effKeyBits;
					}

					return new AlgorithmIdentifier(macOID, new RC2CBCParameter(parameterVersion, rc2Spec.getIV()));
				}

				return new AlgorithmIdentifier(macOID, new RC2CBCParameter(rc2Spec.getIV()));
			}

			throw new IllegalStateException("unknown parameter spec: " + paramSpec);
		}

		public virtual SecretKeyFactory createSecretKeyFactory(string keyFactoryAlgorithm)
		{
			return helper.createSecretKeyFactory(keyFactoryAlgorithm);
		}

		public virtual byte[] calculateDerivedKey(int schemeID, char[] password, AlgorithmIdentifier derivationAlgorithm, int keySize)
		{
			PBKDF2Params @params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());

			try
			{
				SecretKeyFactory keyFact;

				if (schemeID == PasswordRecipient_Fields.PKCS5_SCHEME2)
				{
					keyFact = helper.createSecretKeyFactory("PBKDF2with8BIT");
				}
				else
				{
					keyFact = helper.createSecretKeyFactory((string)PBKDF2_ALG_NAMES.get(@params.getPrf()));
				}

				SecretKey key = keyFact.generateSecret(new PBEKeySpec(password, @params.getSalt(), @params.getIterationCount().intValue(), keySize));

				return key.getEncoded();
			}
			catch (GeneralSecurityException e)
			{
				 throw new CMSException("Unable to calculate derived key from password: " + e.Message, e);
			}
		}

		public interface JCECallback
		{
			object doInJCE();
		}
	}

}