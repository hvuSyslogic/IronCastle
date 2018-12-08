using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.kisa;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.nsri;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.misc;

using System;

namespace org.bouncycastle.jcajce.provider.keystore.bcfks
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using EncryptedObjectStoreData = org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
	using EncryptedPrivateKeyData = org.bouncycastle.asn1.bc.EncryptedPrivateKeyData;
	using EncryptedSecretKeyData = org.bouncycastle.asn1.bc.EncryptedSecretKeyData;
	using ObjectData = org.bouncycastle.asn1.bc.ObjectData;
	using ObjectDataSequence = org.bouncycastle.asn1.bc.ObjectDataSequence;
	using ObjectStore = org.bouncycastle.asn1.bc.ObjectStore;
	using ObjectStoreData = org.bouncycastle.asn1.bc.ObjectStoreData;
	using ObjectStoreIntegrityCheck = org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
	using PbkdMacIntegrityCheck = org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
	using SecretKeyData = org.bouncycastle.asn1.bc.SecretKeyData;
	using CCMParameters = org.bouncycastle.asn1.cms.CCMParameters;
	using KISAObjectIdentifiers = org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using ScryptParams = org.bouncycastle.asn1.misc.ScryptParams;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NSRIObjectIdentifiers = org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using EncryptionScheme = org.bouncycastle.asn1.pkcs.EncryptionScheme;
	using KeyDerivationFunc = org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using PKCS5S2ParametersGenerator = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
	using SCrypt = org.bouncycastle.crypto.generators.SCrypt;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using PBKDF2Config = org.bouncycastle.crypto.util.PBKDF2Config;
	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;
	using ScryptConfig = org.bouncycastle.crypto.util.ScryptConfig;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	public class BcFKSKeyStoreSpi : KeyStoreSpi
	{
		private static readonly Map<string, ASN1ObjectIdentifier> oidMap = new HashMap<string, ASN1ObjectIdentifier>();
		private static readonly Map<ASN1ObjectIdentifier, string> publicAlgMap = new HashMap<ASN1ObjectIdentifier, string>();

		static BcFKSKeyStoreSpi()
		{
			// Note: AES handled inline
			oidMap.put("DESEDE", OIWObjectIdentifiers_Fields.desEDE);
			oidMap.put("TRIPLEDES", OIWObjectIdentifiers_Fields.desEDE);
			oidMap.put("TDEA", OIWObjectIdentifiers_Fields.desEDE);
			oidMap.put("HMACSHA1", PKCSObjectIdentifiers_Fields.id_hmacWithSHA1);
			oidMap.put("HMACSHA224", PKCSObjectIdentifiers_Fields.id_hmacWithSHA224);
			oidMap.put("HMACSHA256", PKCSObjectIdentifiers_Fields.id_hmacWithSHA256);
			oidMap.put("HMACSHA384", PKCSObjectIdentifiers_Fields.id_hmacWithSHA384);
			oidMap.put("HMACSHA512", PKCSObjectIdentifiers_Fields.id_hmacWithSHA512);
			oidMap.put("SEED", KISAObjectIdentifiers_Fields.id_seedCBC);

			oidMap.put("CAMELLIA.128", NTTObjectIdentifiers_Fields.id_camellia128_cbc);
			oidMap.put("CAMELLIA.192", NTTObjectIdentifiers_Fields.id_camellia192_cbc);
			oidMap.put("CAMELLIA.256", NTTObjectIdentifiers_Fields.id_camellia256_cbc);

			oidMap.put("ARIA.128", NSRIObjectIdentifiers_Fields.id_aria128_cbc);
			oidMap.put("ARIA.192", NSRIObjectIdentifiers_Fields.id_aria192_cbc);
			oidMap.put("ARIA.256", NSRIObjectIdentifiers_Fields.id_aria256_cbc);

			publicAlgMap.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			publicAlgMap.put(X9ObjectIdentifiers_Fields.id_ecPublicKey, "EC");
			publicAlgMap.put(OIWObjectIdentifiers_Fields.elGamalAlgorithm, "DH");
			publicAlgMap.put(PKCSObjectIdentifiers_Fields.dhKeyAgreement, "DH");
			publicAlgMap.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
		}

		private static string getPublicKeyAlg(ASN1ObjectIdentifier oid)
		{
			string algName = (string)publicAlgMap.get(oid);

			if (!string.ReferenceEquals(algName, null))
			{
				return algName;
			}

			return oid.getId();
		}

		private static readonly BigInteger CERTIFICATE = BigInteger.valueOf(0);
		private static readonly BigInteger PRIVATE_KEY = BigInteger.valueOf(1);
		private static readonly BigInteger SECRET_KEY = BigInteger.valueOf(2);
		private static readonly BigInteger PROTECTED_PRIVATE_KEY = BigInteger.valueOf(3);
		private static readonly BigInteger PROTECTED_SECRET_KEY = BigInteger.valueOf(4);

		private readonly BouncyCastleProvider provider;
		private readonly Map<string, ObjectData> entries = new HashMap<string, ObjectData>();
		private readonly Map<string, PrivateKey> privateKeyCache = new HashMap<string, PrivateKey>();

		private AlgorithmIdentifier hmacAlgorithm;
		private KeyDerivationFunc hmacPkbdAlgorithm;
		private DateTime creationDate;
		private DateTime lastModifiedDate;
		private ASN1ObjectIdentifier storeEncryptionAlgorithm = NISTObjectIdentifiers_Fields.id_aes256_CCM;

		public BcFKSKeyStoreSpi(BouncyCastleProvider provider)
		{
			this.provider = provider;
		}

		public virtual Key engineGetKey(string alias, char[] password)
		{
			ObjectData ent = (ObjectData)entries.get(alias);

			if (ent != null)
			{
				if (ent.getType().Equals(PRIVATE_KEY) || ent.getType().Equals(PROTECTED_PRIVATE_KEY))
				{
					PrivateKey cachedKey = (PrivateKey)privateKeyCache.get(alias);
					if (cachedKey != null)
					{
						return cachedKey;
					}

					EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
					EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfo.getInstance(encPrivData.getEncryptedPrivateKeyInfo());

					try
					{
						PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(decryptData("PRIVATE_KEY_ENCRYPTION", encInfo.getEncryptionAlgorithm(), password, encInfo.getEncryptedData()));

						KeyFactory kFact;
						if (provider != null)
						{
							kFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), provider);
						}
						else
						{
							kFact = KeyFactory.getInstance(getPublicKeyAlg(pInfo.getPrivateKeyAlgorithm().getAlgorithm()));
						}

						PrivateKey privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(pInfo.getEncoded()));

						// check that the key pair and the certificate public key are consistent
						// TODO: new ConsistentKeyPair(engineGetCertificate(alias).getPublicKey(), privateKey);

						privateKeyCache.put(alias, privateKey);

						return privateKey;
					}
					catch (Exception e)
					{
						throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover private key (" + alias + "): " + e.Message);
					}
				}
				else if (ent.getType().Equals(SECRET_KEY) || ent.getType().Equals(PROTECTED_SECRET_KEY))
				{
					EncryptedSecretKeyData encKeyData = EncryptedSecretKeyData.getInstance(ent.getData());

					try
					{
						SecretKeyData keyData = SecretKeyData.getInstance(decryptData("SECRET_KEY_ENCRYPTION", encKeyData.getKeyEncryptionAlgorithm(), password, encKeyData.getEncryptedKeyData()));
						SecretKeyFactory kFact;
						if (provider != null)
						{
							kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId(), provider);
						}
						else
						{
							kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId());
						}

						return kFact.generateSecret(new SecretKeySpec(keyData.getKeyBytes(), keyData.getKeyAlgorithm().getId()));
					}
					catch (Exception e)
					{
						throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): " + e.Message);
					}
				}
				else
				{
					throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): type not recognized");
				}
			}

			return null;
		}

		public virtual Certificate[] engineGetCertificateChain(string alias)
		{
			ObjectData ent = (ObjectData)entries.get(alias);

			if (ent != null)
			{
				if (ent.getType().Equals(PRIVATE_KEY) || ent.getType().Equals(PROTECTED_PRIVATE_KEY))
				{
					EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
					Certificate[] certificates = encPrivData.getCertificateChain();
					Certificate[] chain = new X509Certificate[certificates.Length];

					for (int i = 0; i != chain.Length; i++)
					{
						chain[i] = decodeCertificate(certificates[i]);
					}

					return chain;
				}
			}

			return null;
		}

		public virtual Certificate engineGetCertificate(string s)
		{
			ObjectData ent = (ObjectData)entries.get(s);

			if (ent != null)
			{
				if (ent.getType().Equals(PRIVATE_KEY) || ent.getType().Equals(PROTECTED_PRIVATE_KEY))
				{
					EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
					Certificate[] certificates = encPrivData.getCertificateChain();

					return decodeCertificate(certificates[0]);
				}
				else if (ent.getType().Equals(CERTIFICATE))
				{
					return decodeCertificate(ent.getData());
				}
			}

			return null;
		}

		private Certificate decodeCertificate(object cert)
		{
			if (provider != null)
			{
				try
				{
					CertificateFactory certFact = CertificateFactory.getInstance("X.509", provider);

					return certFact.generateCertificate(new ByteArrayInputStream(Certificate.getInstance(cert).getEncoded()));
				}
				catch (Exception)
				{
					return null;
				}
			}
			else
			{
				try
				{
					CertificateFactory certFact = CertificateFactory.getInstance("X.509");

					return certFact.generateCertificate(new ByteArrayInputStream(Certificate.getInstance(cert).getEncoded()));
				}
				catch (Exception)
				{
					return null;
				}
			}
		}

		public virtual DateTime engineGetCreationDate(string s)
		{
			ObjectData ent = (ObjectData)entries.get(s);

			if (ent != null)
			{
				try
				{
					// we return last modified as it represents date current state of entry was created
					return ent.getLastModifiedDate().getDate();
				}
				catch (ParseException)
				{
					return DateTime.Now; // it's here, but...
				}
			}

			return null;
		}

		public virtual void engineSetKeyEntry(string alias, Key key, char[] password, Certificate[] chain)
		{
			DateTime creationDate = DateTime.Now;
			DateTime lastEditDate = creationDate;

			ObjectData entry = (ObjectData)entries.get(alias);
			if (entry != null)
			{
				creationDate = extractCreationDate(entry, creationDate);
			}

			privateKeyCache.remove(alias);

			if (key is PrivateKey)
			{
				if (chain == null)
				{
					throw new KeyStoreException("BCFKS KeyStore requires a certificate chain for private key storage.");
				}

				try
				{
					// check that the key pair and the certificate public are consistent
					// TODO: new ConsistentKeyPair(chain[0].getPublicKey(), (PrivateKey)key);

					byte[] encodedKey = key.getEncoded();

					KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBKDF2, 256 / 8);
					byte[] keyBytes = generateKey(pbkdAlgId, "PRIVATE_KEY_ENCRYPTION", ((password != null) ? password : new char[0]), 32);

					EncryptedPrivateKeyInfo keyInfo;
					if (storeEncryptionAlgorithm.Equals(NISTObjectIdentifiers_Fields.id_aes256_CCM))
					{
						Cipher c = createCipher("AES/CCM/NoPadding", keyBytes);

						byte[] encryptedKey = c.doFinal(encodedKey);

						AlgorithmParameters algParams = c.getParameters();

						PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_CCM, CCMParameters.getInstance(algParams.getEncoded())));

						keyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encryptedKey);
					}
					else
					{
						Cipher c = createCipher("AESKWP", keyBytes);

						byte[] encryptedKey = c.doFinal(encodedKey);

						PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_wrap_pad));

						keyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encryptedKey);
					}

					EncryptedPrivateKeyData keySeq = createPrivateKeySequence(keyInfo, chain);

					entries.put(alias, new ObjectData(PRIVATE_KEY, alias, creationDate, lastEditDate, keySeq.getEncoded(), null));
				}
				catch (Exception e)
				{
					throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + e.ToString(), e);
				}
			}
			else if (key is SecretKey)
			{
				if (chain != null)
				{
					throw new KeyStoreException("BCFKS KeyStore cannot store certificate chain with secret key.");
				}

				try
				{
					byte[] encodedKey = key.getEncoded();

					KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBKDF2, 256 / 8);
					byte[] keyBytes = generateKey(pbkdAlgId, "SECRET_KEY_ENCRYPTION", ((password != null) ? password : new char[0]), 32);

					string keyAlg = Strings.toUpperCase(key.getAlgorithm());
					SecretKeyData secKeyData;

					if (keyAlg.IndexOf("AES", StringComparison.Ordinal) > -1)
					{
						secKeyData = new SecretKeyData(NISTObjectIdentifiers_Fields.aes, encodedKey);
					}
					else
					{
						ASN1ObjectIdentifier algOid = (ASN1ObjectIdentifier)oidMap.get(keyAlg);
						if (algOid != null)
						{
							secKeyData = new SecretKeyData(algOid, encodedKey);
						}
						else
						{
							algOid = (ASN1ObjectIdentifier)oidMap.get(keyAlg + "." + (encodedKey.Length * 8));
							if (algOid != null)
							{
								secKeyData = new SecretKeyData(algOid, encodedKey);
							}
							else
							{
								throw new KeyStoreException("BCFKS KeyStore cannot recognize secret key (" + keyAlg + ") for storage.");
							}
						}
					}

					EncryptedSecretKeyData keyData;
					if (storeEncryptionAlgorithm.Equals(NISTObjectIdentifiers_Fields.id_aes256_CCM))
					{
						Cipher c = createCipher("AES/CCM/NoPadding", keyBytes);

						byte[] encryptedKey = c.doFinal(secKeyData.getEncoded());

						AlgorithmParameters algParams = c.getParameters();

						PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_CCM, CCMParameters.getInstance(algParams.getEncoded())));

						keyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encryptedKey);
					}
					else
					{
						Cipher c = createCipher("AESKWP", keyBytes);

						byte[] encryptedKey = c.doFinal(secKeyData.getEncoded());

						PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_wrap_pad));

						keyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encryptedKey);
					}
					entries.put(alias, new ObjectData(SECRET_KEY, alias, creationDate, lastEditDate, keyData.getEncoded(), null));
				}
				catch (Exception e)
				{
					throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + e.ToString(), e);
				}
			}
			else
			{
				throw new KeyStoreException("BCFKS KeyStore unable to recognize key.");
			}

			lastModifiedDate = lastEditDate;
		}

		private Cipher createCipher(string algorithm, byte[] keyBytes)
		{
			Cipher c;
			if (provider == null)
			{
				c = Cipher.getInstance(algorithm);
			}
			else
			{
				c = Cipher.getInstance(algorithm, provider);
			}

			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));

			return c;
		}

		private SecureRandom getDefaultSecureRandom()
		{
			return CryptoServicesRegistrar.getSecureRandom();
		}

		private EncryptedPrivateKeyData createPrivateKeySequence(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] chain)
		{
			Certificate[] certChain = new Certificate[chain.Length];
			for (int i = 0; i != chain.Length; i++)
			{
				certChain[i] = Certificate.getInstance(chain[i].getEncoded());
			}

			return new EncryptedPrivateKeyData(encryptedPrivateKeyInfo, certChain);
		}

		public virtual void engineSetKeyEntry(string alias, byte[] keyBytes, Certificate[] chain)
		{
			DateTime creationDate = DateTime.Now;
			DateTime lastEditDate = creationDate;

			ObjectData entry = (ObjectData)entries.get(alias);
			if (entry != null)
			{
				creationDate = extractCreationDate(entry, creationDate);
			}

			if (chain != null)
			{
				EncryptedPrivateKeyInfo encInfo;

				try
				{
					encInfo = EncryptedPrivateKeyInfo.getInstance(keyBytes);
				}
				catch (Exception e)
				{
					throw new ExtKeyStoreException("BCFKS KeyStore private key encoding must be an EncryptedPrivateKeyInfo.", e);
				}

				try
				{
					privateKeyCache.remove(alias);
					entries.put(alias, new ObjectData(PROTECTED_PRIVATE_KEY, alias, creationDate, lastEditDate, createPrivateKeySequence(encInfo, chain).getEncoded(), null));
				}
				catch (Exception e)
				{
					throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.ToString(), e);
				}
			}
			else
			{
				try
				{
					entries.put(alias, new ObjectData(PROTECTED_SECRET_KEY, alias, creationDate, lastEditDate, keyBytes, null));
				}
				catch (Exception e)
				{
					throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.ToString(), e);
				}
			}

			lastModifiedDate = lastEditDate;
		}

		public virtual void engineSetCertificateEntry(string alias, Certificate certificate)
		{
			ObjectData entry = (ObjectData)entries.get(alias);
			DateTime creationDate = DateTime.Now;
			DateTime lastEditDate = creationDate;

			if (entry != null)
			{
				if (!entry.getType().Equals(CERTIFICATE))
				{
					throw new KeyStoreException("BCFKS KeyStore already has a key entry with alias " + alias);
				}

				creationDate = extractCreationDate(entry, creationDate);
			}

			try
			{
				entries.put(alias, new ObjectData(CERTIFICATE, alias, creationDate, lastEditDate, certificate.getEncoded(), null));
			}
			catch (CertificateEncodingException e)
			{
				throw new ExtKeyStoreException("BCFKS KeyStore unable to handle certificate: " + e.Message, e);
			}

			lastModifiedDate = lastEditDate;
		}

		private DateTime extractCreationDate(ObjectData entry, DateTime creationDate)
		{
			try
			{
				creationDate = entry.getCreationDate().getDate();
			}
			catch (ParseException)
			{
				// this should never happen, if it does we'll leave creation date unmodified and hope for the best.
			}
			return creationDate;
		}

		public virtual void engineDeleteEntry(string alias)
		{
			ObjectData entry = (ObjectData)entries.get(alias);

			if (entry == null)
			{
				return;
			}

			privateKeyCache.remove(alias);
			entries.remove(alias);

			lastModifiedDate = DateTime.Now;
		}

		public virtual Enumeration<string> engineAliases()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.Iterator<String> it = new java.util.HashSet(entries.keySet()).iterator();
			Iterator<string> it = (new HashSet(entries.keySet())).iterator();

			return new EnumerationAnonymousInnerClass(this, it);
		}

		public class EnumerationAnonymousInnerClass : Enumeration
		{
			private readonly BcFKSKeyStoreSpi outerInstance;

			private Iterator<string> it;

			public EnumerationAnonymousInnerClass(BcFKSKeyStoreSpi outerInstance, Iterator<string> it)
			{
				this.outerInstance = outerInstance;
				this.it = it;
			}

			public bool hasMoreElements()
			{
				return it.hasNext();
			}

			public object nextElement()
			{
				return it.next();
			}
		}

		public virtual bool engineContainsAlias(string alias)
		{
			if (string.ReferenceEquals(alias, null))
			{
				throw new NullPointerException("alias value is null");
			}

			return entries.containsKey(alias);
		}

		public virtual int engineSize()
		{
			return entries.size();
		}

		public virtual bool engineIsKeyEntry(string alias)
		{
			ObjectData ent = (ObjectData)entries.get(alias);

			if (ent != null)
			{
				BigInteger entryType = ent.getType();
				return entryType.Equals(PRIVATE_KEY) || entryType.Equals(SECRET_KEY) || entryType.Equals(PROTECTED_PRIVATE_KEY) || entryType.Equals(PROTECTED_SECRET_KEY);
			}

			return false;
		}

		public virtual bool engineIsCertificateEntry(string alias)
		{
			ObjectData ent = (ObjectData)entries.get(alias);

			if (ent != null)
			{
				return ent.getType().Equals(CERTIFICATE);
			}

			return false;
		}

		public virtual string engineGetCertificateAlias(Certificate certificate)
		{
			if (certificate == null)
			{
				return null;
			}

			byte[] encodedCert;
			try
			{
				encodedCert = certificate.getEncoded();
			}
			catch (CertificateEncodingException)
			{
				return null;
			}

			for (Iterator<string> it = entries.keySet().iterator(); it.hasNext();)
			{
				string alias = (string)it.next();
				ObjectData ent = (ObjectData)entries.get(alias);

				if (ent.getType().Equals(CERTIFICATE))
				{
					if (Arrays.areEqual(ent.getData(), encodedCert))
					{
						return alias;
					}
				}
				else if (ent.getType().Equals(PRIVATE_KEY) || ent.getType().Equals(PROTECTED_PRIVATE_KEY))
				{
					try
					{
						EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
						if (Arrays.areEqual(encPrivData.getCertificateChain()[0].toASN1Primitive().getEncoded(), encodedCert))
						{
							return alias;
						}
					}
					catch (IOException)
					{
						// ignore - this should never happen
					}
				}
			}

			return null;
		}

		private byte[] generateKey(KeyDerivationFunc pbkdAlgorithm, string purpose, char[] password, int defKeySize)
		{
			byte[] encPassword = PBEParametersGenerator.PKCS12PasswordToBytes(password);
			byte[] differentiator = PBEParametersGenerator.PKCS12PasswordToBytes(purpose.ToCharArray());

			int keySizeInBytes = defKeySize;

			if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(pbkdAlgorithm.getAlgorithm()))
			{
				ScryptParams @params = ScryptParams.getInstance(pbkdAlgorithm.getParameters());

				if (@params.getKeyLength() != null)
				{
					keySizeInBytes = @params.getKeyLength().intValue();
				}
				else if (keySizeInBytes == -1)
				{
					throw new IOException("no keyLength found in ScryptParams");
				}
				return SCrypt.generate(Arrays.concatenate(encPassword, differentiator), @params.getSalt(), @params.getCostParameter().intValue(), @params.getBlockSize().intValue(), @params.getBlockSize().intValue(), keySizeInBytes);
			}
			else if (pbkdAlgorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2))
			{
				PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbkdAlgorithm.getParameters());

				if (pbkdf2Params.getKeyLength() != null)
				{
					keySizeInBytes = pbkdf2Params.getKeyLength().intValue();
				}
				else if (keySizeInBytes == -1)
				{
					throw new IOException("no keyLength found in PBKDF2Params");
				}

				if (pbkdf2Params.getPrf().getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512))
				{
					PKCS5S2ParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA512Digest());

					pGen.init(Arrays.concatenate(encPassword, differentiator), pbkdf2Params.getSalt(), pbkdf2Params.getIterationCount().intValue());

					return ((KeyParameter)pGen.generateDerivedParameters(keySizeInBytes * 8)).getKey();
				}
				else if (pbkdf2Params.getPrf().getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512))
				{
					PKCS5S2ParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA3Digest(512));

					pGen.init(Arrays.concatenate(encPassword, differentiator), pbkdf2Params.getSalt(), pbkdf2Params.getIterationCount().intValue());

					return ((KeyParameter)pGen.generateDerivedParameters(keySizeInBytes * 8)).getKey();
				}
				else
				{
					throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD PRF: " + pbkdf2Params.getPrf().getAlgorithm());
				}
			}
			else
			{
				throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD.");
			}
		}

		private void verifyMac(byte[] content, PbkdMacIntegrityCheck integrityCheck, char[] password)
		{
			byte[] check = calculateMac(content, integrityCheck.getMacAlgorithm(), integrityCheck.getPbkdAlgorithm(), password);

			if (!Arrays.constantTimeAreEqual(check, integrityCheck.getMac()))
			{
				throw new IOException("BCFKS KeyStore corrupted: MAC calculation failed.");
			}
		}

		private byte[] calculateMac(byte[] content, AlgorithmIdentifier algorithm, KeyDerivationFunc pbkdAlgorithm, char[] password)
		{
			string algorithmId = algorithm.getAlgorithm().getId();

			Mac mac;
			if (provider != null)
			{
				mac = Mac.getInstance(algorithmId, provider);
			}
			else
			{
				mac = Mac.getInstance(algorithmId);
			}

			try
			{
				// no default key size for MAC.
				mac.init(new SecretKeySpec(generateKey(pbkdAlgorithm, "INTEGRITY_CHECK", ((password != null) ? password : new char[0]), -1), algorithmId));
			}
			catch (InvalidKeyException e)
			{
				throw new IOException("Cannot set up MAC calculation: " + e.Message);
			}

			return mac.doFinal(content);
		}

		private char[] extractPassword(KeyStore.LoadStoreParameter bcParam)
		{
			KeyStore.ProtectionParameter protParam = bcParam.getProtectionParameter();

			if (protParam == null)
			{
				return null;
			}
			else if (protParam is KeyStore.PasswordProtection)
			{
				return ((KeyStore.PasswordProtection)protParam).getPassword();
			}
			else if (protParam is KeyStore.CallbackHandlerProtection)
			{
				CallbackHandler handler = ((KeyStore.CallbackHandlerProtection)protParam).getCallbackHandler();

				PasswordCallback passwordCallback = new PasswordCallback("password: ", false);

				try
				{
					handler.handle(new Callback[]{passwordCallback});

					return passwordCallback.getPassword();
				}
				catch (UnsupportedCallbackException e)
				{
					throw new IllegalArgumentException("PasswordCallback not recognised: " + e.Message, e);
				}
			}
			else
			{
				throw new IllegalArgumentException("no support for protection parameter of type " + protParam.GetType().getName());
			}
		}

		public virtual void engineStore(KeyStore.LoadStoreParameter parameter)
		{
			if (parameter == null)
			{
				throw new IllegalArgumentException("'parameter' arg cannot be null");
			}

			if (parameter is BCFKSStoreParameter)
			{
				BCFKSStoreParameter bcParam = (BCFKSStoreParameter)parameter;

				char[] password = extractPassword(parameter);

				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bcParam.getStorePBKDFConfig(), 512 / 8);

				engineStore(bcParam.getOutputStream(), password);
			}
			else if (parameter is BCFKSLoadStoreParameter)
			{
				BCFKSLoadStoreParameter bcParam = (BCFKSLoadStoreParameter)parameter;

				char[] password = extractPassword(bcParam);

				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bcParam.getStorePBKDFConfig(), 512 / 8);

				if (bcParam.getStoreEncryptionAlgorithm() == BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM)
				{
					storeEncryptionAlgorithm = NISTObjectIdentifiers_Fields.id_aes256_CCM;
				}
				else
				{
					storeEncryptionAlgorithm = NISTObjectIdentifiers_Fields.id_aes256_wrap_pad;
				}

				if (bcParam.getStoreMacAlgorithm() == BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512)
				{
					hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE);
				}
				else
				{
					hmacAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, DERNull.INSTANCE);
				}

				engineStore(bcParam.getOutputStream(), password);
			}
			else if (parameter is BCLoadStoreParameter)
			{
				BCLoadStoreParameter bcParam = (BCLoadStoreParameter)parameter;

				engineStore(bcParam.getOutputStream(), extractPassword(parameter));
			}
			else
			{
				throw new IllegalArgumentException("no support for 'parameter' of type " + parameter.GetType().getName());
			}

		}

		public virtual void engineStore(OutputStream outputStream, char[] password)
		{
			if (creationDate == null)
			{
				throw new IOException("KeyStore not initialized");
			}

			ObjectData[] dataArray = (ObjectData[])entries.values().toArray(new ObjectData[entries.size()]);

			KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, 256 / 8);
			byte[] keyBytes = generateKey(pbkdAlgId, "STORE_ENCRYPTION", ((password != null) ? password : new char[0]), 256 / 8);

			ObjectStoreData storeData = new ObjectStoreData(hmacAlgorithm, creationDate, lastModifiedDate, new ObjectDataSequence(dataArray), null);
			EncryptedObjectStoreData encStoreData;

			try
			{
				if (storeEncryptionAlgorithm.Equals(NISTObjectIdentifiers_Fields.id_aes256_CCM))
				{
					Cipher c = createCipher("AES/CCM/NoPadding", keyBytes);

					byte[] encOut = c.doFinal(storeData.getEncoded());

					AlgorithmParameters algorithmParameters = c.getParameters();

					PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_CCM, CCMParameters.getInstance(algorithmParameters.getEncoded())));

					encStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encOut);
				}
				else
				{
					Cipher c = createCipher("AESKWP", keyBytes);

					byte[] encOut = c.doFinal(storeData.getEncoded());
					PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers_Fields.id_aes256_wrap_pad));

					encStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, pbeParams), encOut);
				}
			}
			catch (NoSuchPaddingException e)
			{
				throw new NoSuchAlgorithmException(e.ToString());
			}
			catch (BadPaddingException e)
			{
				throw new IOException(e.ToString());
			}
			catch (IllegalBlockSizeException e)
			{
				throw new IOException(e.ToString());
			}
			catch (InvalidKeyException e)
			{
				throw new IOException(e.ToString());
			}

			// update the salt
			if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(hmacPkbdAlgorithm.getAlgorithm()))
			{
				ScryptParams sParams = ScryptParams.getInstance(hmacPkbdAlgorithm.getParameters());

				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, sParams.getKeyLength().intValue());
			}
			else
			{
				PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(hmacPkbdAlgorithm.getParameters());

				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, pbkdf2Params.getKeyLength().intValue());
			}
			byte[] mac = calculateMac(encStoreData.getEncoded(), hmacAlgorithm, hmacPkbdAlgorithm, password);

			ObjectStore store = new ObjectStore(encStoreData, new ObjectStoreIntegrityCheck(new PbkdMacIntegrityCheck(hmacAlgorithm, hmacPkbdAlgorithm, mac)));

			outputStream.write(store.getEncoded());

			outputStream.flush();
		}

		public virtual void engineLoad(KeyStore.LoadStoreParameter parameter)
		{
			if (parameter == null)
			{
				throw new IllegalArgumentException("'parameter' arg cannot be null");
			}

			if (parameter is BCFKSLoadStoreParameter)
			{
				BCFKSLoadStoreParameter bcParam = (BCFKSLoadStoreParameter)parameter;

				char[] password = extractPassword(bcParam);

				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bcParam.getStorePBKDFConfig(), 512 / 8);

				if (bcParam.getStoreEncryptionAlgorithm() == BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM)
				{
					storeEncryptionAlgorithm = NISTObjectIdentifiers_Fields.id_aes256_CCM;
				}
				else
				{
					storeEncryptionAlgorithm = NISTObjectIdentifiers_Fields.id_aes256_wrap_pad;
				}

				if (bcParam.getStoreMacAlgorithm() == BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512)
				{
					hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE);
				}
				else
				{
					hmacAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, DERNull.INSTANCE);
				}

				AlgorithmIdentifier presetHmacAlgorithm = hmacAlgorithm;
				ASN1ObjectIdentifier presetStoreEncryptionAlgorithm = storeEncryptionAlgorithm;

				InputStream inputStream = bcParam.getInputStream();
				engineLoad(inputStream, password);

				if (inputStream != null)
				{
					if (!presetHmacAlgorithm.Equals(hmacAlgorithm) || !isSimilarHmacPbkd(bcParam.getStorePBKDFConfig(), hmacPkbdAlgorithm) || !presetStoreEncryptionAlgorithm.Equals(storeEncryptionAlgorithm))
					{
						throw new IOException("configuration parameters do not match existing store");
					}
				}
			}
			else if (parameter is BCLoadStoreParameter)
			{
				BCLoadStoreParameter bcParam = (BCLoadStoreParameter)parameter;

				engineLoad(bcParam.getInputStream(), extractPassword(parameter));
			}
			else
			{
				throw new IllegalArgumentException("no support for 'parameter' of type " + parameter.GetType().getName());
			}
		}

		private bool isSimilarHmacPbkd(PBKDFConfig storePBKDFConfig, KeyDerivationFunc hmacPkbdAlgorithm)
		{
			if (!storePBKDFConfig.getAlgorithm().Equals(hmacPkbdAlgorithm.getAlgorithm()))
			{
				return false;
			}

			if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(hmacPkbdAlgorithm.getAlgorithm()))
			{
				if (!(storePBKDFConfig is ScryptConfig))
				{
					return false;
				}

				ScryptConfig scryptConfig = (ScryptConfig)storePBKDFConfig;
				ScryptParams sParams = ScryptParams.getInstance(hmacPkbdAlgorithm.getParameters());

				if (scryptConfig.getSaltLength() != sParams.getSalt().Length || scryptConfig.getBlockSize() != sParams.getBlockSize().intValue() || scryptConfig.getCostParameter() != sParams.getCostParameter().intValue() || scryptConfig.getParallelizationParameter() != sParams.getParallelizationParameter().intValue())
				{
					return false;
				}
			}
			else
			{
				if (!(storePBKDFConfig is PBKDF2Config))
				{
					return false;
				}

				PBKDF2Config pbkdf2Config = (PBKDF2Config)storePBKDFConfig;
				PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(hmacPkbdAlgorithm.getParameters());

				if (pbkdf2Config.getSaltLength() != pbkdf2Params.getSalt().Length || pbkdf2Config.getIterationCount() != pbkdf2Params.getIterationCount().intValue())
				{
					return false;
				}
			}

			return true;
		}

		public virtual void engineLoad(InputStream inputStream, char[] password)
		{
			// reset any current values
			entries.clear();
			privateKeyCache.clear();

			lastModifiedDate = creationDate = null;
			hmacAlgorithm = null;

			if (inputStream == null)
			{
				// initialise defaults
				lastModifiedDate = creationDate = DateTime.Now;

				// basic initialisation
				hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE);
				hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBKDF2, 512 / 8);

				return;
			}

			ASN1InputStream aIn = new ASN1InputStream(inputStream);

			ObjectStore store;

			try
			{
				store = ObjectStore.getInstance(aIn.readObject());
			}
			catch (Exception e)
			{
				throw new IOException(e.Message);
			}

			ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();
			if (integrityCheck.getType() == ObjectStoreIntegrityCheck.PBKD_MAC_CHECK)
			{
				PbkdMacIntegrityCheck pbkdMacIntegrityCheck = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

				hmacAlgorithm = pbkdMacIntegrityCheck.getMacAlgorithm();
				hmacPkbdAlgorithm = pbkdMacIntegrityCheck.getPbkdAlgorithm();

				verifyMac(store.getStoreData().toASN1Primitive().getEncoded(), pbkdMacIntegrityCheck, password);
			}
			else
			{
				throw new IOException("BCFKS KeyStore unable to recognize integrity check.");
			}

			ASN1Encodable sData = store.getStoreData();

			ObjectStoreData storeData;
			if (sData is EncryptedObjectStoreData)
			{
				EncryptedObjectStoreData encryptedStoreData = (EncryptedObjectStoreData)sData;
				AlgorithmIdentifier protectAlgId = encryptedStoreData.getEncryptionAlgorithm();

				storeData = ObjectStoreData.getInstance(decryptData("STORE_ENCRYPTION", protectAlgId, password, encryptedStoreData.getEncryptedContent().getOctets()));
			}
			else
			{
				storeData = ObjectStoreData.getInstance(sData);
			}

			try
			{
				creationDate = storeData.getCreationDate().getDate();
				lastModifiedDate = storeData.getLastModifiedDate().getDate();
			}
			catch (ParseException)
			{
				throw new IOException("BCFKS KeyStore unable to parse store data information.");
			}

			if (!storeData.getIntegrityAlgorithm().Equals(hmacAlgorithm))
			{
				throw new IOException("BCFKS KeyStore storeData integrity algorithm does not match store integrity algorithm.");
			}

			for (Iterator it = storeData.getObjectDataSequence().iterator(); it.hasNext();)
			{
				ObjectData objData = ObjectData.getInstance(it.next());

				entries.put(objData.getIdentifier(), objData);
			}
		}

		private byte[] decryptData(string purpose, AlgorithmIdentifier protectAlgId, char[] password, byte[] encryptedData)
		{
			if (!protectAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_PBES2))
			{
				throw new IOException("BCFKS KeyStore cannot recognize protection algorithm.");
			}

			PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(protectAlgId.getParameters());
			EncryptionScheme algId = pbes2Parameters.getEncryptionScheme();

			try
			{
				Cipher c;
				AlgorithmParameters algParams;
				if (algId.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_aes256_CCM))
				{
					if (provider == null)
					{
						c = Cipher.getInstance("AES/CCM/NoPadding");
						algParams = AlgorithmParameters.getInstance("CCM");
					}
					else
					{
						c = Cipher.getInstance("AES/CCM/NoPadding", provider);
						algParams = AlgorithmParameters.getInstance("CCM", provider);
					}

					CCMParameters ccmParameters = CCMParameters.getInstance(algId.getParameters());

					algParams.init(ccmParameters.getEncoded());
				}
				else if (algId.getAlgorithm().Equals(NISTObjectIdentifiers_Fields.id_aes256_wrap_pad))
				{
					if (provider == null)
					{
						c = Cipher.getInstance("AESKWP");
						algParams = null;
					}
					else
					{
						c = Cipher.getInstance("AESKWP", provider);
						algParams = null;
					}
				}
				else
				{
					throw new IOException("BCFKS KeyStore cannot recognize protection encryption algorithm.");
				}

				byte[] keyBytes = generateKey(pbes2Parameters.getKeyDerivationFunc(), purpose, ((password != null) ? password : new char[0]), 32);

				c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), algParams);

				byte[] rv = c.doFinal(encryptedData);
				return rv;
			}
			catch (IOException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new IOException(e.ToString());
			}
		}

		private KeyDerivationFunc generatePkbdAlgorithmIdentifier(PBKDFConfig pbkdfConfig, int keySizeInBytes)
		{
			if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(pbkdfConfig.getAlgorithm()))
			{
				ScryptConfig scryptConfig = (ScryptConfig)pbkdfConfig;

				byte[] pbkdSalt = new byte[scryptConfig.getSaltLength()];
				getDefaultSecureRandom().nextBytes(pbkdSalt);

				ScryptParams @params = new ScryptParams(pbkdSalt, scryptConfig.getCostParameter(), scryptConfig.getBlockSize(), scryptConfig.getParallelizationParameter(), keySizeInBytes);

				return new KeyDerivationFunc(MiscObjectIdentifiers_Fields.id_scrypt, @params);
			}
			else
			{
				PBKDF2Config pbkdf2Config = (PBKDF2Config)pbkdfConfig;

				byte[] pbkdSalt = new byte[pbkdf2Config.getSaltLength()];
				getDefaultSecureRandom().nextBytes(pbkdSalt);

				return new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, new PBKDF2Params(pbkdSalt, pbkdf2Config.getIterationCount(), keySizeInBytes, pbkdf2Config.getPRF()));
			}
		}

		private KeyDerivationFunc generatePkbdAlgorithmIdentifier(KeyDerivationFunc baseAlg, int keySizeInBytes)
		{
			if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(baseAlg.getAlgorithm()))
			{
				ScryptParams oldParams = ScryptParams.getInstance(baseAlg.getParameters());

				byte[] pbkdSalt = new byte[oldParams.getSalt().Length];
				getDefaultSecureRandom().nextBytes(pbkdSalt);

				ScryptParams @params = new ScryptParams(pbkdSalt, oldParams.getCostParameter(), oldParams.getBlockSize(), oldParams.getParallelizationParameter(), BigInteger.valueOf(keySizeInBytes));

				return new KeyDerivationFunc(MiscObjectIdentifiers_Fields.id_scrypt, @params);
			}
			else
			{
				PBKDF2Params oldParams = PBKDF2Params.getInstance(baseAlg.getParameters());

				byte[] pbkdSalt = new byte[oldParams.getSalt().Length];
				getDefaultSecureRandom().nextBytes(pbkdSalt);

				PBKDF2Params @params = new PBKDF2Params(pbkdSalt, oldParams.getIterationCount().intValue(), keySizeInBytes, oldParams.getPrf());
				return new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, @params);
			}
		}

		private KeyDerivationFunc generatePkbdAlgorithmIdentifier(ASN1ObjectIdentifier derivationAlgorithm, int keySizeInBytes)
		{
			byte[] pbkdSalt = new byte[512 / 8];
			getDefaultSecureRandom().nextBytes(pbkdSalt);

			if (PKCSObjectIdentifiers_Fields.id_PBKDF2.Equals(derivationAlgorithm))
			{
				return new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, new PBKDF2Params(pbkdSalt, 50 * 1024, keySizeInBytes, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE)));
			}
			else
			{
				throw new IllegalStateException("unknown derivation algorithm: " + derivationAlgorithm);
			}
		}

		public class Std : BcFKSKeyStoreSpi
		{
			public Std() : base(new BouncyCastleProvider())
			{
			}
		}

		public class Def : BcFKSKeyStoreSpi
		{
			public Def() : base(null)
			{
			}
		}

		public class SharedKeyStoreSpi : BcFKSKeyStoreSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
		{
			internal readonly Map<string, byte[]> cache;
			internal readonly byte[] seedKey;

			public SharedKeyStoreSpi(BouncyCastleProvider provider) : base(provider)
			{

				try
				{
					this.seedKey = new byte[32];

					if (provider != null)
					{
						SecureRandom.getInstance("DEFAULT", provider).nextBytes(seedKey);
					}
					else
					{
						SecureRandom.getInstance("DEFAULT").nextBytes(seedKey);
					}
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new IllegalArgumentException("can't create cert factory - " + e.ToString());
				}

				this.cache = new HashMap<string, byte[]>();
			}

			public override void engineDeleteEntry(string alias)
			{
				throw new KeyStoreException("delete operation not supported in shared mode");
			}

			public override void engineSetKeyEntry(string alias, Key key, char[] password, Certificate[] chain)
			{
				throw new KeyStoreException("set operation not supported in shared mode");
			}

			public override void engineSetKeyEntry(string alias, byte[] keyEncoding, Certificate[] chain)
			{
				throw new KeyStoreException("set operation not supported in shared mode");
			}

			public override void engineSetCertificateEntry(string alias, Certificate cert)
			{
				throw new KeyStoreException("set operation not supported in shared mode");
			}

			public override Key engineGetKey(string alias, char[] password)
			{
				byte[] mac;

				try
				{
					mac = calculateMac(alias, password);
				}
				catch (InvalidKeyException e)
				{ // this should never happen...
					throw new UnrecoverableKeyException("unable to recover key (" + alias + "): " + e.Message);
				}

				if (cache.containsKey(alias))
				{
					byte[] hash = cache.get(alias);

					if (!Arrays.constantTimeAreEqual(hash, mac))
					{
						throw new UnrecoverableKeyException("unable to recover key (" + alias + ")");
					}
				}

				Key key = base.engineGetKey(alias, password);

				if (key != null && !cache.containsKey(alias))
				{
					cache.put(alias, mac);
				}

				return key;
			}

			public virtual byte[] calculateMac(string alias, char[] password)
			{
				byte[] encoding;
				if (password != null)
				{
					encoding = Arrays.concatenate(Strings.toUTF8ByteArray(password), Strings.toUTF8ByteArray(alias));
				}
				else
				{
					encoding = Arrays.concatenate(seedKey, Strings.toUTF8ByteArray(alias));
				}

				return SCrypt.generate(encoding, seedKey, 16384, 8, 1, 32);
			}
		}

		public class StdShared : SharedKeyStoreSpi
		{
			public StdShared() : base(new BouncyCastleProvider())
			{
			}
		}

		public class DefShared : SharedKeyStoreSpi
		{
			public DefShared() : base(null)
			{
			}
		}

		public class ExtKeyStoreException : KeyStoreException
		{
			internal readonly Exception cause;

			public ExtKeyStoreException(string msg, Exception cause) : base(msg)
			{
				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}