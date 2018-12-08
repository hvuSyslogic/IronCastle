using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.iana;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.cert.crmf.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using AlgorithmParametersUtils = org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public class CRMFHelper
	{
		protected internal static readonly Map BASE_CIPHER_NAMES = new HashMap();
		protected internal static readonly Map CIPHER_ALG_NAMES = new HashMap();
		protected internal static readonly Map DIGEST_ALG_NAMES = new HashMap();
		protected internal static readonly Map KEY_ALG_NAMES = new HashMap();
		protected internal static readonly Map MAC_ALG_NAMES = new HashMap();

		static CRMFHelper()
		{
			BASE_CIPHER_NAMES.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, "DESEDE");
			BASE_CIPHER_NAMES.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, "AES");
			BASE_CIPHER_NAMES.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, "AES");
			BASE_CIPHER_NAMES.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, "AES");

			CIPHER_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AES/CBC/PKCS5Padding");
			CIPHER_ALG_NAMES.put(new ASN1ObjectIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption.getId()), "RSA/ECB/PKCS1Padding");

			DIGEST_ALG_NAMES.put(OIWObjectIdentifiers_Fields.idSHA1, "SHA1");
			DIGEST_ALG_NAMES.put(NISTObjectIdentifiers_Fields.id_sha224, "SHA224");
			DIGEST_ALG_NAMES.put(NISTObjectIdentifiers_Fields.id_sha256, "SHA256");
			DIGEST_ALG_NAMES.put(NISTObjectIdentifiers_Fields.id_sha384, "SHA384");
			DIGEST_ALG_NAMES.put(NISTObjectIdentifiers_Fields.id_sha512, "SHA512");

			MAC_ALG_NAMES.put(IANAObjectIdentifiers_Fields.hmacSHA1, "HMACSHA1");
			MAC_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, "HMACSHA1");
			MAC_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, "HMACSHA224");
			MAC_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, "HMACSHA256");
			MAC_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, "HMACSHA384");
			MAC_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, "HMACSHA512");

			KEY_ALG_NAMES.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			KEY_ALG_NAMES.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
		}

		private JcaJceHelper helper;

		public CRMFHelper(JcaJceHelper helper)
		{
			this.helper = helper;
		}

		public virtual PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
		{
			try
			{
				X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
				AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithm();

				return createKeyFactory(keyAlg.getAlgorithm()).generatePublic(xspec);
			}
			catch (Exception e)
			{
				throw new CRMFException("invalid key: " + e.Message, e);
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
				throw new CRMFException("cannot create cipher: " + e.Message, e);
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
				throw new CRMFException("cannot create key generator: " + e.Message, e);
			}
		}



//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: javax.crypto.Cipher createContentCipher(final java.security.Key sKey, final org.bouncycastle.asn1.x509.AlgorithmIdentifier encryptionAlgID) throws org.bouncycastle.cert.crmf.CRMFException
		public virtual Cipher createContentCipher(Key sKey, AlgorithmIdentifier encryptionAlgID)
		{
			return (Cipher)execute(new JCECallbackAnonymousInnerClass(this, sKey, encryptionAlgID));
		}

		public class JCECallbackAnonymousInnerClass : JCECallback
		{
			private readonly CRMFHelper outerInstance;

			private Key sKey;
			private AlgorithmIdentifier encryptionAlgID;

			public JCECallbackAnonymousInnerClass(CRMFHelper outerInstance, Key sKey, AlgorithmIdentifier encryptionAlgID)
			{
				this.outerInstance = outerInstance;
				this.sKey = sKey;
				this.encryptionAlgID = encryptionAlgID;
			}

			public object doInJCE()
			{
				Cipher cipher = outerInstance.createCipher(encryptionAlgID.getAlgorithm());
				ASN1Primitive sParams = (ASN1Primitive)encryptionAlgID.getParameters();
				ASN1ObjectIdentifier encAlg = encryptionAlgID.getAlgorithm();

				if (sParams != null && !(sParams is ASN1Null))
				{
					try
					{
						AlgorithmParameters @params = outerInstance.createAlgorithmParameters(encryptionAlgID.getAlgorithm());

						try
						{
							AlgorithmParametersUtils.loadParameters(@params, sParams);
						}
						catch (IOException e)
						{
							throw new CRMFException("error decoding algorithm parameters.", e);
						}

						cipher.init(Cipher.DECRYPT_MODE, sKey, @params);
					}
					catch (NoSuchAlgorithmException e)
					{
						if (encAlg.Equals(CMSAlgorithm.DES_EDE3_CBC) || encAlg.Equals(CMSAlgorithm.IDEA_CBC) || encAlg.Equals(CMSAlgorithm.AES128_CBC) || encAlg.Equals(CMSAlgorithm.AES192_CBC) || encAlg.Equals(CMSAlgorithm.AES256_CBC))
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
					if (encAlg.Equals(CMSAlgorithm.DES_EDE3_CBC) || encAlg.Equals(CMSAlgorithm.IDEA_CBC) || encAlg.Equals(CMSAlgorithm.CAST5_CBC))
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

		public virtual KeyFactory createKeyFactory(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string algName = (string)KEY_ALG_NAMES.get(algorithm);

				if (!string.ReferenceEquals(algName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createKeyFactory(algName);
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
				throw new CRMFException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual MessageDigest createDigest(ASN1ObjectIdentifier algorithm)
		{
			try
			{
				string digestName = (string)DIGEST_ALG_NAMES.get(algorithm);

				if (!string.ReferenceEquals(digestName, null))
				{
					try
					{
						// this is reversed as the Sun policy files now allow unlimited strength RSA
						return helper.createDigest(digestName);
					}
					catch (NoSuchAlgorithmException)
					{
						// Ignore
					}
				}
				return helper.createDigest(algorithm.getId());
			}
			catch (GeneralSecurityException e)
			{
				throw new CRMFException("cannot create cipher: " + e.Message, e);
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
				throw new CRMFException("cannot create mac: " + e.Message, e);
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
						throw new CRMFException("parameters generation error: " + e, e);
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
				throw new CRMFException("exception creating algorithm parameter generator: " + e, e);
			}
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier encryptionOID, AlgorithmParameters @params)
		{
			ASN1Encodable asn1Params;
			if (@params != null)
			{
				try
				{
					asn1Params = AlgorithmParametersUtils.extractParameters(@params);
				}
				catch (IOException e)
				{
					throw new CRMFException("cannot encode parameters: " + e.Message, e);
				}
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
				throw new CRMFException("can't find algorithm.", e);
			}
			catch (InvalidKeyException e)
			{
				throw new CRMFException("key invalid in message.", e);
			}
			catch (NoSuchProviderException e)
			{
				throw new CRMFException("can't find provider.", e);
			}
			catch (NoSuchPaddingException e)
			{
				throw new CRMFException("required padding not supported.", e);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new CRMFException("algorithm parameters invalid.", e);
			}
			catch (InvalidParameterSpecException e)
			{
				throw new CRMFException("MAC algorithm parameter spec invalid.", e);
			}
		}

		public interface JCECallback
		{
			object doInJCE();
		}
	}

}