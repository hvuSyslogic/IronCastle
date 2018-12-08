using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.jcajce.provider.keystore.pkcs12
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using BEROutputStream = org.bouncycastle.asn1.BEROutputStream;
	using DERBMPString = org.bouncycastle.asn1.DERBMPString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GOST28147Parameters = org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AuthenticatedSafe = org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
	using CertBag = org.bouncycastle.asn1.pkcs.CertBag;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using EncryptedData = org.bouncycastle.asn1.pkcs.EncryptedData;
	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Pfx = org.bouncycastle.asn1.pkcs.Pfx;
	using SafeBag = org.bouncycastle.asn1.pkcs.SafeBag;
	using ASN1Dump = org.bouncycastle.asn1.util.ASN1Dump;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using GOST28147ParameterSpec = org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
	using PBKDF2KeySpec = org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using BCKeyStore = org.bouncycastle.jce.interfaces.BCKeyStore;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JDKPKCS12StoreParameter = org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Properties = org.bouncycastle.util.Properties;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class PKCS12KeyStoreSpi : KeyStoreSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore
	{
		internal const string PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";

		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		private const int SALT_SIZE = 20;
		private const int MIN_ITERATIONS = 50 * 1024;

		private static readonly DefaultSecretKeyProvider keySizeProvider = new DefaultSecretKeyProvider();

		private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
		private Hashtable localIds = new Hashtable();
		private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
		private Hashtable chainCerts = new Hashtable();
		private Hashtable keyCerts = new Hashtable();

		//
		// generic object types
		//
		internal const int NULL = 0;
		internal const int CERTIFICATE = 1;
		internal const int KEY = 2;
		internal const int SECRET = 3;
		internal const int SEALED = 4;

		//
		// key types
		//
		internal const int KEY_PRIVATE = 0;
		internal const int KEY_PUBLIC = 1;
		internal const int KEY_SECRET = 2;

		protected internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

		// use of final causes problems with JDK 1.2 compiler
		private CertificateFactory certFact;
		private ASN1ObjectIdentifier keyAlgorithm;
		private ASN1ObjectIdentifier certAlgorithm;

		private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
		private int itCount = 2 * MIN_ITERATIONS;
		private int saltLength = 20;

		public class CertId
		{
			private readonly PKCS12KeyStoreSpi outerInstance;

			internal byte[] id;

			public CertId(PKCS12KeyStoreSpi outerInstance, PublicKey key)
			{
				this.outerInstance = outerInstance;
				this.id = outerInstance.createSubjectKeyId(key).getKeyIdentifier();
			}

			public CertId(PKCS12KeyStoreSpi outerInstance, byte[] id)
			{
				this.outerInstance = outerInstance;
				this.id = id;
			}

			public override int GetHashCode()
			{
				return Arrays.GetHashCode(id);
			}

			public override bool Equals(object o)
			{
				if (o == this)
				{
					return true;
				}

				if (!(o is CertId))
				{
					return false;
				}

				CertId cId = (CertId)o;

				return Arrays.areEqual(id, cId.id);
			}
		}

		public PKCS12KeyStoreSpi(Provider provider, ASN1ObjectIdentifier keyAlgorithm, ASN1ObjectIdentifier certAlgorithm)
		{
			this.keyAlgorithm = keyAlgorithm;
			this.certAlgorithm = certAlgorithm;

			try
			{
				if (provider != null)
				{
					certFact = CertificateFactory.getInstance("X.509", provider);
				}
				else
				{
					certFact = CertificateFactory.getInstance("X.509");
				}
			}
			catch (Exception e)
			{
				throw new IllegalArgumentException("can't create cert factory - " + e.ToString());
			}
		}

		private SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

				return new SubjectKeyIdentifier(getDigest(info));
			}
			catch (Exception)
			{
				throw new RuntimeException("error creating key");
			}
		}

		private static byte[] getDigest(SubjectPublicKeyInfo spki)
		{
			Digest digest = DigestFactory.createSHA1();
			byte[] resBuf = new byte[digest.getDigestSize()];

			byte[] bytes = spki.getPublicKeyData().getBytes();
			digest.update(bytes, 0, bytes.Length);
			digest.doFinal(resBuf, 0);
			return resBuf;
		}

		public virtual void setRandom(SecureRandom rand)
		{
			this.random = rand;
		}

		public virtual Enumeration engineAliases()
		{
			Hashtable tab = new Hashtable();

			Enumeration e = certs.keys();
			while (e.hasMoreElements())
			{
				tab.put(e.nextElement(), "cert");
			}

			e = keys.keys();
			while (e.hasMoreElements())
			{
				string a = (string)e.nextElement();
				if (tab.get(a) == null)
				{
					tab.put(a, "key");
				}
			}

			return tab.keys();
		}

		public virtual bool engineContainsAlias(string alias)
		{
			return (certs.get(alias) != null || keys.get(alias) != null);
		}

		/// <summary>
		/// this is not quite complete - we should follow up on the chain, a bit
		/// tricky if a certificate appears in more than one chain... the store method
		/// now prunes out unused certificates from the chain map if they are present.
		/// </summary>
		public virtual void engineDeleteEntry(string alias)
		{
			Key k = (Key)keys.remove(alias);

			Certificate c = (Certificate)certs.remove(alias);

			if (c != null)
			{
				chainCerts.remove(new CertId(this, c.getPublicKey()));
			}

			if (k != null)
			{
				string id = (string)localIds.remove(alias);
				if (!string.ReferenceEquals(id, null))
				{
					c = (Certificate)keyCerts.remove(id);
				}
				if (c != null)
				{
					chainCerts.remove(new CertId(this, c.getPublicKey()));
				}
			}
		}

		/// <summary>
		/// simply return the cert for the private key
		/// </summary>
		public virtual Certificate engineGetCertificate(string alias)
		{
			if (string.ReferenceEquals(alias, null))
			{
				throw new IllegalArgumentException("null alias passed to getCertificate.");
			}

			Certificate c = (Certificate)certs.get(alias);

			//
			// look up the key table - and try the local key id
			//
			if (c == null)
			{
				string id = (string)localIds.get(alias);
				if (!string.ReferenceEquals(id, null))
				{
					c = (Certificate)keyCerts.get(id);
				}
				else
				{
					c = (Certificate)keyCerts.get(alias);
				}
			}

			return c;
		}

		public virtual string engineGetCertificateAlias(Certificate cert)
		{
			Enumeration c = certs.elements();
			Enumeration k = certs.keys();

			while (c.hasMoreElements())
			{
				Certificate tc = (Certificate)c.nextElement();
				string ta = (string)k.nextElement();

				if (tc.Equals(cert))
				{
					return ta;
				}
			}

			c = keyCerts.elements();
			k = keyCerts.keys();

			while (c.hasMoreElements())
			{
				Certificate tc = (Certificate)c.nextElement();
				string ta = (string)k.nextElement();

				if (tc.Equals(cert))
				{
					return ta;
				}
			}

			return null;
		}

		public virtual Certificate[] engineGetCertificateChain(string alias)
		{
			if (string.ReferenceEquals(alias, null))
			{
				throw new IllegalArgumentException("null alias passed to getCertificateChain.");
			}

			if (!engineIsKeyEntry(alias))
			{
				return null;
			}

			Certificate c = engineGetCertificate(alias);

			if (c != null)
			{
				Vector cs = new Vector();

				while (c != null)
				{
					X509Certificate x509c = (X509Certificate)c;
					Certificate nextC = null;

					byte[] bytes = x509c.getExtensionValue(Extension.authorityKeyIdentifier.getId());
					if (bytes != null)
					{
						try
						{
							ASN1InputStream aIn = new ASN1InputStream(bytes);

							byte[] authBytes = ((ASN1OctetString)aIn.readObject()).getOctets();
							aIn = new ASN1InputStream(authBytes);

							AuthorityKeyIdentifier id = AuthorityKeyIdentifier.getInstance(aIn.readObject());
							if (id.getKeyIdentifier() != null)
							{
								nextC = (Certificate)chainCerts.get(new CertId(this, id.getKeyIdentifier()));
							}

						}
						catch (IOException e)
						{
							throw new RuntimeException(e.ToString());
						}
					}

					if (nextC == null)
					{
						//
						// no authority key id, try the Issuer DN
						//
						Principal i = x509c.getIssuerDN();
						Principal s = x509c.getSubjectDN();

						if (!i.Equals(s))
						{
							Enumeration e = chainCerts.keys();

							while (e.hasMoreElements())
							{
								X509Certificate crt = (X509Certificate)chainCerts.get(e.nextElement());
								Principal sub = crt.getSubjectDN();
								if (sub.Equals(i))
								{
									try
									{
										x509c.verify(crt.getPublicKey());
										nextC = crt;
										break;
									}
									catch (Exception)
									{
										// continue
									}
								}
							}
						}
					}

					if (cs.contains(c))
					{
						c = null; // we've got a certificate chain loop time to stop
					}
					else
					{
						cs.addElement(c);
						if (nextC != c) // self signed - end of the chain
						{
							c = nextC;
						}
						else
						{
							c = null;
						}
					}
				}

				Certificate[] certChain = new Certificate[cs.size()];

				for (int i = 0; i != certChain.Length; i++)
				{
					certChain[i] = (Certificate)cs.elementAt(i);
				}

				return certChain;
			}

			return null;
		}

		public virtual DateTime engineGetCreationDate(string alias)
		{
			if (string.ReferenceEquals(alias, null))
			{
				throw new NullPointerException("alias == null");
			}
			if (keys.get(alias) == null && certs.get(alias) == null)
			{
				return null;
			}
			return DateTime.Now;
		}

		public virtual Key engineGetKey(string alias, char[] password)
		{
			if (string.ReferenceEquals(alias, null))
			{
				throw new IllegalArgumentException("null alias passed to getKey.");
			}

			return (Key)keys.get(alias);
		}

		public virtual bool engineIsCertificateEntry(string alias)
		{
			return (certs.get(alias) != null && keys.get(alias) == null);
		}

		public virtual bool engineIsKeyEntry(string alias)
		{
			return (keys.get(alias) != null);
		}

		public virtual void engineSetCertificateEntry(string alias, Certificate cert)
		{
			if (keys.get(alias) != null)
			{
				throw new KeyStoreException("There is a key entry with the name " + alias + ".");
			}

			certs.put(alias, cert);
			chainCerts.put(new CertId(this, cert.getPublicKey()), cert);
		}

		public virtual void engineSetKeyEntry(string alias, byte[] key, Certificate[] chain)
		{
			throw new RuntimeException("operation not supported");
		}

		public virtual void engineSetKeyEntry(string alias, Key key, char[] password, Certificate[] chain)
		{
			if (!(key is PrivateKey))
			{
				throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
			}

			if ((key is PrivateKey) && (chain == null))
			{
				throw new KeyStoreException("no certificate chain for private key");
			}

			if (keys.get(alias) != null)
			{
				engineDeleteEntry(alias);
			}

			keys.put(alias, key);
			if (chain != null)
			{
				certs.put(alias, chain[0]);

				for (int i = 0; i != chain.Length; i++)
				{
					chainCerts.put(new CertId(this, chain[i].getPublicKey()), chain[i]);
				}
			}
		}

		public virtual int engineSize()
		{
			Hashtable tab = new Hashtable();

			Enumeration e = certs.keys();
			while (e.hasMoreElements())
			{
				tab.put(e.nextElement(), "cert");
			}

			e = keys.keys();
			while (e.hasMoreElements())
			{
				string a = (string)e.nextElement();
				if (tab.get(a) == null)
				{
					tab.put(a, "key");
				}
			}

			return tab.size();
		}

		public virtual PrivateKey unwrapKey(AlgorithmIdentifier algId, byte[] org, char[] password, bool wrongPKCS12Zero)
		{
			ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
			try
			{
				if (algorithm.on(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds))
				{
					PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
					PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), validateIterationCount(pbeParams.getIterations()));

					Cipher cipher = helper.createCipher(algorithm.getId());

					PKCS12Key key = new PKCS12Key(password, wrongPKCS12Zero);

					cipher.init(Cipher.UNWRAP_MODE, key, defParams);

					// we pass "" as the key algorithm type as it is unknown at this point
					return (PrivateKey)cipher.unwrap(PKCSObjectIdentifiers_Fields.data, "", Cipher.PRIVATE_KEY);
				}
				else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.id_PBES2))
				{

					Cipher cipher = createCipher(Cipher.UNWRAP_MODE, password, algId);

					// we pass "" as the key algorithm type as it is unknown at this point
					return (PrivateKey)cipher.unwrap(PKCSObjectIdentifiers_Fields.data, "", Cipher.PRIVATE_KEY);
				}
			}
			catch (Exception e)
			{
				throw new IOException("exception unwrapping private key - " + e.ToString());
			}

			throw new IOException("exception unwrapping private key - cannot recognise: " + algorithm);
		}

		public virtual byte[] wrapKey(string algorithm, Key key, PKCS12PBEParams pbeParams, char[] password)
		{
			PBEKeySpec pbeSpec = new PBEKeySpec(password);
			byte[] @out;

			try
			{
				SecretKeyFactory keyFact = helper.createSecretKeyFactory(algorithm);
				PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());

				Cipher cipher = helper.createCipher(algorithm);

				cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), defParams);

				@out = cipher.wrap(key);
			}
			catch (Exception e)
			{
				throw new IOException("exception encrypting data - " + e.ToString());
			}

			return @out;
		}

		public virtual byte[] cryptData(bool forEncryption, AlgorithmIdentifier algId, char[] password, bool wrongPKCS12Zero, byte[] org)
		{
			ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
			int mode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

			if (algorithm.on(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds))
			{
				PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
				try
				{
					PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());
					PKCS12Key key = new PKCS12Key(password, wrongPKCS12Zero);

					Cipher cipher = helper.createCipher(algorithm.getId());

					cipher.init(mode, key, defParams);
					return cipher.doFinal(PKCSObjectIdentifiers_Fields.data);
				}
				catch (Exception e)
				{
					throw new IOException("exception decrypting data - " + e.ToString());
				}
			}
			else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.id_PBES2))
			{
				try
				{
					Cipher cipher = createCipher(mode, password, algId);

					return cipher.doFinal(PKCSObjectIdentifiers_Fields.data);
				}
				catch (Exception e)
				{
					throw new IOException("exception decrypting data - " + e.ToString());
				}
			}
			else
			{
				throw new IOException("unknown PBE algorithm: " + algorithm);
			}
		}

		private Cipher createCipher(int mode, char[] password, AlgorithmIdentifier algId)
		{
			PBES2Parameters alg = PBES2Parameters.getInstance(algId.getParameters());
			PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
			AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

			SecretKeyFactory keyFact = helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
			SecretKey key;

			if (func.isDefaultPrf())
			{
				key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), validateIterationCount(func.getIterationCount()), keySizeProvider.getKeySize(encScheme)));
			}
			else
			{
				key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), validateIterationCount(func.getIterationCount()), keySizeProvider.getKeySize(encScheme), func.getPrf()));
			}

			Cipher cipher = Cipher.getInstance(alg.getEncryptionScheme().getAlgorithm().getId());

			ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
			if (encParams is ASN1OctetString)
			{
				cipher.init(mode, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
			}
			else
			{
				// TODO: at the moment it's just GOST, but...
				GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

				cipher.init(mode, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
			}
			return cipher;
		}

		public virtual void engineLoad(InputStream stream, char[] password)
		{
			if (stream == null) // just initialising
			{
				return;
			}

			if (password == null)
			{
				throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
			}

			BufferedInputStream bufIn = new BufferedInputStream(stream);

			bufIn.mark(10);

			int head = bufIn.read();

			if (head != 0x30)
			{
				throw new IOException("stream does not represent a PKCS12 key store");
			}

			bufIn.reset();

			ASN1InputStream bIn = new ASN1InputStream(bufIn);

			Pfx bag;
			try
			{
				bag = Pfx.getInstance(bIn.readObject());
			}
			catch (Exception e)
			{
				throw new IOException(e.Message);
			}

			ContentInfo info = bag.getAuthSafe();
			Vector chain = new Vector();
			bool unmarkedKey = false;
			bool wrongPKCS12Zero = false;

			if (bag.getMacData() != null) // check the mac code
			{
				MacData mData = bag.getMacData();
				DigestInfo dInfo = mData.getMac();
				macAlgorithm = dInfo.getAlgorithmId();
				byte[] salt = mData.getSalt();
				itCount = validateIterationCount(mData.getIterationCount());
				saltLength = salt.Length;

				byte[] PKCSObjectIdentifiers_Fields.data = ((ASN1OctetString)info.getContent()).getOctets();

				try
				{
					byte[] res = calculatePbeMac(macAlgorithm.getAlgorithm(), salt, itCount, password, false, PKCSObjectIdentifiers_Fields.data);
					byte[] dig = dInfo.getDigest();

					if (!Arrays.constantTimeAreEqual(res, dig))
					{
						if (password.Length > 0)
						{
							throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
						}

						// Try with incorrect zero length password
						res = calculatePbeMac(macAlgorithm.getAlgorithm(), salt, itCount, password, true, PKCSObjectIdentifiers_Fields.data);

						if (!Arrays.constantTimeAreEqual(res, dig))
						{
							throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
						}

						wrongPKCS12Zero = true;
					}
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new IOException("error constructing MAC: " + e.ToString());
				}
			}

			keys = new IgnoresCaseHashtable();
			localIds = new Hashtable();

			if (info.getContentType().Equals(PKCSObjectIdentifiers_Fields.data))
			{
				bIn = new ASN1InputStream(((ASN1OctetString)info.getContent()).getOctets());

				AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(bIn.readObject());
				ContentInfo[] c = authSafe.getContentInfo();

				for (int i = 0; i != c.Length; i++)
				{
					if (c[i].getContentType().Equals(PKCSObjectIdentifiers_Fields.data))
					{
						ASN1InputStream dIn = new ASN1InputStream(((ASN1OctetString)c[i].getContent()).getOctets());
						ASN1Sequence seq = (ASN1Sequence)dIn.readObject();

						for (int j = 0; j != seq.size(); j++)
						{
							SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
							if (b.getBagId().Equals(PKCSObjectIdentifiers_Fields.pkcs8ShroudedKeyBag))
							{
								EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
								PrivateKey privKey = unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password, wrongPKCS12Zero);

								//
								// set the attributes on the key
								//
								string alias = null;
								ASN1OctetString localId = null;

								if (b.getBagAttributes() != null)
								{
									Enumeration e = b.getBagAttributes().getObjects();
									while (e.hasMoreElements())
									{
										ASN1Sequence sq = (ASN1Sequence)e.nextElement();
										ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
										ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
										ASN1Primitive attr = null;

										if (attrSet.size() > 0)
										{
											attr = (ASN1Primitive)attrSet.getObjectAt(0);

											if (privKey is PKCS12BagAttributeCarrier)
											{
												PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;
												ASN1Encodable existing = bagAttr.getBagAttribute(aOid);
												if (existing != null)
												{
													// OK, but the value has to be the same
													if (!existing.toASN1Primitive().Equals(attr))
													{
														throw new IOException("attempt to add existing attribute with different value");
													}
												}
												else
												{
													bagAttr.setBagAttribute(aOid, attr);
												}
											}
										}

										if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName))
										{
											alias = ((DERBMPString)attr).getString();
											keys.put(alias, privKey);
										}
										else if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
										{
											localId = (ASN1OctetString)attr;
										}
									}
								}

								if (localId != null)
								{
									string name = StringHelper.NewString(Hex.encode(localId.getOctets()));

									if (string.ReferenceEquals(alias, null))
									{
										keys.put(name, privKey);
									}
									else
									{
										localIds.put(alias, name);
									}
								}
								else
								{
									unmarkedKey = true;
									keys.put("unmarked", privKey);
								}
							}
							else if (b.getBagId().Equals(PKCSObjectIdentifiers_Fields.certBag))
							{
								chain.addElement(b);
							}
							else
							{
								JavaSystem.@out.println("extra in data " + b.getBagId());
								JavaSystem.@out.println(ASN1Dump.dumpAsString(b));
							}
						}
					}
					else if (c[i].getContentType().Equals(PKCSObjectIdentifiers_Fields.encryptedData))
					{
						EncryptedData d = EncryptedData.getInstance(c[i].getContent());
						byte[] octets = cryptData(false, d.getEncryptionAlgorithm(), password, wrongPKCS12Zero, d.getContent().getOctets());
						ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(octets);

						for (int j = 0; j != seq.size(); j++)
						{
							SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));

							if (b.getBagId().Equals(PKCSObjectIdentifiers_Fields.certBag))
							{
								chain.addElement(b);
							}
							else if (b.getBagId().Equals(PKCSObjectIdentifiers_Fields.pkcs8ShroudedKeyBag))
							{
								EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
								PrivateKey privKey = unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password, wrongPKCS12Zero);

								//
								// set the attributes on the key
								//
								PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;
								string alias = null;
								ASN1OctetString localId = null;

								Enumeration e = b.getBagAttributes().getObjects();
								while (e.hasMoreElements())
								{
									ASN1Sequence sq = (ASN1Sequence)e.nextElement();
									ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
									ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
									ASN1Primitive attr = null;

									if (attrSet.size() > 0)
									{
										attr = (ASN1Primitive)attrSet.getObjectAt(0);

										ASN1Encodable existing = bagAttr.getBagAttribute(aOid);
										if (existing != null)
										{
											// OK, but the value has to be the same
											if (!existing.toASN1Primitive().Equals(attr))
											{
												throw new IOException("attempt to add existing attribute with different value");
											}
										}
										else
										{
											bagAttr.setBagAttribute(aOid, attr);
										}
									}

									if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName))
									{
										alias = ((DERBMPString)attr).getString();
										keys.put(alias, privKey);
									}
									else if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
									{
										localId = (ASN1OctetString)attr;
									}
								}

								string name = StringHelper.NewString(Hex.encode(localId.getOctets()));

								if (string.ReferenceEquals(alias, null))
								{
									keys.put(name, privKey);
								}
								else
								{
									localIds.put(alias, name);
								}
							}
							else if (b.getBagId().Equals(PKCSObjectIdentifiers_Fields.keyBag))
							{
								PrivateKeyInfo kInfo = PrivateKeyInfo.getInstance(b.getBagValue());
								PrivateKey privKey = BouncyCastleProvider.getPrivateKey(kInfo);

								//
								// set the attributes on the key
								//
								PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;
								string alias = null;
								ASN1OctetString localId = null;

								Enumeration e = b.getBagAttributes().getObjects();
								while (e.hasMoreElements())
								{
									ASN1Sequence sq = ASN1Sequence.getInstance(e.nextElement());
									ASN1ObjectIdentifier aOid = ASN1ObjectIdentifier.getInstance(sq.getObjectAt(0));
									ASN1Set attrSet = ASN1Set.getInstance(sq.getObjectAt(1));
									ASN1Primitive attr = null;

									if (attrSet.size() > 0)
									{
										attr = (ASN1Primitive)attrSet.getObjectAt(0);

										ASN1Encodable existing = bagAttr.getBagAttribute(aOid);
										if (existing != null)
										{
											// OK, but the value has to be the same
											if (!existing.toASN1Primitive().Equals(attr))
											{
												throw new IOException("attempt to add existing attribute with different value");
											}
										}
										else
										{
											bagAttr.setBagAttribute(aOid, attr);
										}

										if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName))
										{
											alias = ((DERBMPString)attr).getString();
											keys.put(alias, privKey);
										}
										else if (aOid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
										{
											localId = (ASN1OctetString)attr;
										}
									}
								}

								string name = StringHelper.NewString(Hex.encode(localId.getOctets()));

								if (string.ReferenceEquals(alias, null))
								{
									keys.put(name, privKey);
								}
								else
								{
									localIds.put(alias, name);
								}
							}
							else
							{
								JavaSystem.@out.println("extra in encryptedData " + b.getBagId());
								JavaSystem.@out.println(ASN1Dump.dumpAsString(b));
							}
						}
					}
					else
					{
						JavaSystem.@out.println("extra " + c[i].getContentType().getId());
						JavaSystem.@out.println("extra " + ASN1Dump.dumpAsString(c[i].getContent()));
					}
				}
			}

			certs = new IgnoresCaseHashtable();
			chainCerts = new Hashtable();
			keyCerts = new Hashtable();

			for (int i = 0; i != chain.size(); i++)
			{
				SafeBag b = (SafeBag)chain.elementAt(i);
				CertBag cb = CertBag.getInstance(b.getBagValue());

				if (!cb.getCertId().Equals(PKCSObjectIdentifiers_Fields.x509Certificate))
				{
					throw new RuntimeException("Unsupported certificate type: " + cb.getCertId());
				}

				Certificate cert;

				try
				{
					ByteArrayInputStream cIn = new ByteArrayInputStream(((ASN1OctetString)cb.getCertValue()).getOctets());
					cert = certFact.generateCertificate(cIn);
				}
				catch (Exception e)
				{
					throw new RuntimeException(e.ToString());
				}

				//
				// set the attributes
				//
				ASN1OctetString localId = null;
				string alias = null;

				if (b.getBagAttributes() != null)
				{
					Enumeration e = b.getBagAttributes().getObjects();
					while (e.hasMoreElements())
					{
						ASN1Sequence sq = ASN1Sequence.getInstance(e.nextElement());
						ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sq.getObjectAt(0));
						ASN1Set attrSet = ASN1Set.getInstance(sq.getObjectAt(1));

						if (attrSet.size() > 0) // sometimes this is empty!
						{
							ASN1Primitive attr = (ASN1Primitive)attrSet.getObjectAt(0);
							PKCS12BagAttributeCarrier bagAttr = null;

							if (cert is PKCS12BagAttributeCarrier)
							{
								bagAttr = (PKCS12BagAttributeCarrier)cert;

								ASN1Encodable existing = bagAttr.getBagAttribute(oid);
								if (existing != null)
								{
									// OK, but the value has to be the same
									if (!existing.toASN1Primitive().Equals(attr))
									{
										throw new IOException("attempt to add existing attribute with different value");
									}
								}
								else
								{
									bagAttr.setBagAttribute(oid, attr);
								}
							}

							if (oid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName))
							{
								alias = ((DERBMPString)attr).getString();
							}
							else if (oid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
							{
								localId = (ASN1OctetString)attr;
							}
						}
					}
				}

				chainCerts.put(new CertId(this, cert.getPublicKey()), cert);

				if (unmarkedKey)
				{
					if (keyCerts.isEmpty())
					{
						string name = StringHelper.NewString(Hex.encode(createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier()));

						keyCerts.put(name, cert);
						keys.put(name, keys.remove("unmarked"));
					}
				}
				else
				{
					//
					// the local key id needs to override the friendly name
					//
					if (localId != null)
					{
						string name = StringHelper.NewString(Hex.encode(localId.getOctets()));

						keyCerts.put(name, cert);
					}
					if (!string.ReferenceEquals(alias, null))
					{
						certs.put(alias, cert);
					}
				}
			}
		}

		private int validateIterationCount(BigInteger i)
		{
			int count = i.intValue();

			if (count < 0)
			{
				throw new IllegalStateException("negative iteration count found");
			}

			BigInteger maxValue = Properties.asBigInteger(PKCS12_MAX_IT_COUNT_PROPERTY);
			if (maxValue != null)
			{
				if (maxValue.intValue() < count)
				{
					throw new IllegalStateException("iteration count " + count + " greater than " + maxValue.intValue());
				}
			}

			return count;
		}

		public virtual void engineStore(KeyStore.LoadStoreParameter param)
		{
			if (param == null)
			{
				throw new IllegalArgumentException("'param' arg cannot be null");
			}

			if (!(param is PKCS12StoreParameter || param is JDKPKCS12StoreParameter))
			{
				throw new IllegalArgumentException("No support for 'param' of type " + param.GetType().getName());
			}

			PKCS12StoreParameter bcParam;

			if (param is PKCS12StoreParameter)
			{
				bcParam = (PKCS12StoreParameter)param;
			}
			else
			{
				bcParam = new PKCS12StoreParameter(((JDKPKCS12StoreParameter)param).getOutputStream(), param.getProtectionParameter(), ((JDKPKCS12StoreParameter)param).isUseDEREncoding());
			}

			char[] password;
			KeyStore.ProtectionParameter protParam = param.getProtectionParameter();
			if (protParam == null)
			{
				password = null;
			}
			else if (protParam is KeyStore.PasswordProtection)
			{
				password = ((KeyStore.PasswordProtection)protParam).getPassword();
			}
			else
			{
				throw new IllegalArgumentException("No support for protection parameter of type " + protParam.GetType().getName());
			}

			doStore(bcParam.getOutputStream(), password, bcParam.isForDEREncoding());
		}

		public virtual void engineStore(OutputStream stream, char[] password)
		{
			doStore(stream, password, false);
		}

		private void doStore(OutputStream stream, char[] password, bool useDEREncoding)
		{
			if (password == null)
			{
				throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
			}

			//
			// handle the key
			//
			ASN1EncodableVector keyS = new ASN1EncodableVector();

			Enumeration ks = keys.keys();

			while (ks.hasMoreElements())
			{
				byte[] kSalt = new byte[SALT_SIZE];

				random.nextBytes(kSalt);

				string name = (string)ks.nextElement();
				PrivateKey privKey = (PrivateKey)keys.get(name);
				PKCS12PBEParams kParams = new PKCS12PBEParams(kSalt, MIN_ITERATIONS);
				byte[] kBytes = wrapKey(keyAlgorithm.getId(), privKey, kParams, password);
				AlgorithmIdentifier kAlgId = new AlgorithmIdentifier(keyAlgorithm, kParams.toASN1Primitive());
				EncryptedPrivateKeyInfo kInfo = new EncryptedPrivateKeyInfo(kAlgId, kBytes);
				bool attrSet = false;
				ASN1EncodableVector kName = new ASN1EncodableVector();

				if (privKey is PKCS12BagAttributeCarrier)
				{
					PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)privKey;
					//
					// make sure we are using the local alias on store
					//
					DERBMPString nm = (DERBMPString)bagAttrs.getBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
					if (nm == null || !nm.getString().Equals(name))
					{
						bagAttrs.setBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName, new DERBMPString(name));
					}

					//
					// make sure we have a local key-id
					//
					if (bagAttrs.getBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId) == null)
					{
						Certificate ct = engineGetCertificate(name);

						bagAttrs.setBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId, createSubjectKeyId(ct.getPublicKey()));
					}

					Enumeration e = bagAttrs.getBagAttributeKeys();

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						ASN1EncodableVector kSeq = new ASN1EncodableVector();

						kSeq.add(oid);
						kSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));

						attrSet = true;

						kName.add(new DERSequence(kSeq));
					}
				}

				if (!attrSet)
				{
					//
					// set a default friendly name (from the key id) and local id
					//
					ASN1EncodableVector kSeq = new ASN1EncodableVector();
					Certificate ct = engineGetCertificate(name);

					kSeq.add(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId);
					kSeq.add(new DERSet(createSubjectKeyId(ct.getPublicKey())));

					kName.add(new DERSequence(kSeq));

					kSeq = new ASN1EncodableVector();

					kSeq.add(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
					kSeq.add(new DERSet(new DERBMPString(name)));

					kName.add(new DERSequence(kSeq));
				}

				SafeBag kBag = new SafeBag(PKCSObjectIdentifiers_Fields.pkcs8ShroudedKeyBag, kInfo.toASN1Primitive(), new DERSet(kName));
				keyS.add(kBag);
			}

			byte[] keySEncoded = (new DERSequence(keyS)).getEncoded(ASN1Encoding_Fields.DER);
			BEROctetString keyString = new BEROctetString(keySEncoded);

			//
			// certificate processing
			//
			byte[] cSalt = new byte[SALT_SIZE];

			random.nextBytes(cSalt);

			ASN1EncodableVector certSeq = new ASN1EncodableVector();
			PKCS12PBEParams cParams = new PKCS12PBEParams(cSalt, MIN_ITERATIONS);
			AlgorithmIdentifier cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.toASN1Primitive());
			Hashtable doneCerts = new Hashtable();

			Enumeration cs = keys.keys();
			while (cs.hasMoreElements())
			{
				try
				{
					string name = (string)cs.nextElement();
					Certificate cert = engineGetCertificate(name);
					bool cAttrSet = false;
					CertBag cBag = new CertBag(PKCSObjectIdentifiers_Fields.x509Certificate, new DEROctetString(cert.getEncoded()));
					ASN1EncodableVector fName = new ASN1EncodableVector();

					if (cert is PKCS12BagAttributeCarrier)
					{
						PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
						//
						// make sure we are using the local alias on store
						//
						DERBMPString nm = (DERBMPString)bagAttrs.getBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
						if (nm == null || !nm.getString().Equals(name))
						{
							bagAttrs.setBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName, new DERBMPString(name));
						}

						//
						// make sure we have a local key-id
						//
						if (bagAttrs.getBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId) == null)
						{
							bagAttrs.setBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId, createSubjectKeyId(cert.getPublicKey()));
						}

						Enumeration e = bagAttrs.getBagAttributeKeys();

						while (e.hasMoreElements())
						{
							ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
							ASN1EncodableVector fSeq = new ASN1EncodableVector();

							fSeq.add(oid);
							fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
							fName.add(new DERSequence(fSeq));

							cAttrSet = true;
						}
					}

					if (!cAttrSet)
					{
						ASN1EncodableVector fSeq = new ASN1EncodableVector();

						fSeq.add(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId);
						fSeq.add(new DERSet(createSubjectKeyId(cert.getPublicKey())));
						fName.add(new DERSequence(fSeq));

						fSeq = new ASN1EncodableVector();

						fSeq.add(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
						fSeq.add(new DERSet(new DERBMPString(name)));

						fName.add(new DERSequence(fSeq));
					}

					SafeBag sBag = new SafeBag(PKCSObjectIdentifiers_Fields.certBag, cBag.toASN1Primitive(), new DERSet(fName));

					certSeq.add(sBag);

					doneCerts.put(cert, cert);
				}
				catch (CertificateEncodingException e)
				{
					throw new IOException("Error encoding certificate: " + e.ToString());
				}
			}

			cs = certs.keys();
			while (cs.hasMoreElements())
			{
				try
				{
					string certId = (string)cs.nextElement();
					Certificate cert = (Certificate)certs.get(certId);
					bool cAttrSet = false;

					if (keys.get(certId) != null)
					{
						continue;
					}

					CertBag cBag = new CertBag(PKCSObjectIdentifiers_Fields.x509Certificate, new DEROctetString(cert.getEncoded()));
					ASN1EncodableVector fName = new ASN1EncodableVector();

					if (cert is PKCS12BagAttributeCarrier)
					{
						PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
						//
						// make sure we are using the local alias on store
						//
						DERBMPString nm = (DERBMPString)bagAttrs.getBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
						if (nm == null || !nm.getString().Equals(certId))
						{
							bagAttrs.setBagAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName, new DERBMPString(certId));
						}

						Enumeration e = bagAttrs.getBagAttributeKeys();

						while (e.hasMoreElements())
						{
							ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

							// a certificate not immediately linked to a key doesn't require
							// a localKeyID and will confuse some PKCS12 implementations.
							//
							// If we find one, we'll prune it out.
							if (oid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
							{
								continue;
							}

							ASN1EncodableVector fSeq = new ASN1EncodableVector();

							fSeq.add(oid);
							fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
							fName.add(new DERSequence(fSeq));

							cAttrSet = true;
						}
					}

					if (!cAttrSet)
					{
						ASN1EncodableVector fSeq = new ASN1EncodableVector();

						fSeq.add(PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName);
						fSeq.add(new DERSet(new DERBMPString(certId)));

						fName.add(new DERSequence(fSeq));
					}

					SafeBag sBag = new SafeBag(PKCSObjectIdentifiers_Fields.certBag, cBag.toASN1Primitive(), new DERSet(fName));

					certSeq.add(sBag);

					doneCerts.put(cert, cert);
				}
				catch (CertificateEncodingException e)
				{
					throw new IOException("Error encoding certificate: " + e.ToString());
				}
			}

			Set usedSet = getUsedCertificateSet();

			cs = chainCerts.keys();
			while (cs.hasMoreElements())
			{
				try
				{
					CertId certId = (CertId)cs.nextElement();
					Certificate cert = (Certificate)chainCerts.get(certId);

					if (!usedSet.contains(cert))
					{
						continue;
					}

					if (doneCerts.get(cert) != null)
					{
						continue;
					}

					CertBag cBag = new CertBag(PKCSObjectIdentifiers_Fields.x509Certificate, new DEROctetString(cert.getEncoded()));
					ASN1EncodableVector fName = new ASN1EncodableVector();

					if (cert is PKCS12BagAttributeCarrier)
					{
						PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
						Enumeration e = bagAttrs.getBagAttributeKeys();

						while (e.hasMoreElements())
						{
							ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

							// a certificate not immediately linked to a key doesn't require
							// a localKeyID and will confuse some PKCS12 implementations.
							//
							// If we find one, we'll prune it out.
							if (oid.Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId))
							{
								continue;
							}

							ASN1EncodableVector fSeq = new ASN1EncodableVector();

							fSeq.add(oid);
							fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
							fName.add(new DERSequence(fSeq));
						}
					}

					SafeBag sBag = new SafeBag(PKCSObjectIdentifiers_Fields.certBag, cBag.toASN1Primitive(), new DERSet(fName));

					certSeq.add(sBag);
				}
				catch (CertificateEncodingException e)
				{
					throw new IOException("Error encoding certificate: " + e.ToString());
				}
			}

			byte[] certSeqEncoded = (new DERSequence(certSeq)).getEncoded(ASN1Encoding_Fields.DER);
			byte[] certBytes = cryptData(true, cAlgId, password, false, certSeqEncoded);
			EncryptedData cInfo = new EncryptedData(PKCSObjectIdentifiers_Fields.data, cAlgId, new BEROctetString(certBytes));

			ContentInfo[] info = new ContentInfo[]
			{
				new ContentInfo(PKCSObjectIdentifiers_Fields.data, keyString),
				new ContentInfo(PKCSObjectIdentifiers_Fields.encryptedData, cInfo.toASN1Primitive())
			};

			AuthenticatedSafe auth = new AuthenticatedSafe(info);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream asn1Out;
			if (useDEREncoding)
			{
				asn1Out = new DEROutputStream(bOut);
			}
			else
			{
				asn1Out = new BEROutputStream(bOut);
			}

			asn1Out.writeObject(auth);

			byte[] pkg = bOut.toByteArray();

			ContentInfo mainInfo = new ContentInfo(PKCSObjectIdentifiers_Fields.data, new BEROctetString(pkg));

			//
			// create the mac
			//
			byte[] mSalt = new byte[saltLength];

			random.nextBytes(mSalt);

			byte[] PKCSObjectIdentifiers_Fields.data = ((ASN1OctetString)mainInfo.getContent()).getOctets();

			MacData mData;

			try
			{
				byte[] res = calculatePbeMac(macAlgorithm.getAlgorithm(), mSalt, itCount, password, false, PKCSObjectIdentifiers_Fields.data);

				DigestInfo dInfo = new DigestInfo(macAlgorithm, res);

				mData = new MacData(dInfo, mSalt, itCount);
			}
			catch (Exception e)
			{
				throw new IOException("error constructing MAC: " + e.ToString());
			}

			//
			// output the Pfx
			//
			Pfx pfx = new Pfx(mainInfo, mData);

			if (useDEREncoding)
			{
				asn1Out = new DEROutputStream(stream);
			}
			else
			{
				asn1Out = new BEROutputStream(stream);
			}

			asn1Out.writeObject(pfx);
		}

		private Set getUsedCertificateSet()
		{
			Set usedSet = new HashSet();

			for (Enumeration en = keys.keys(); en.hasMoreElements();)
			{
				string alias = (string)en.nextElement();

					Certificate[] certs = engineGetCertificateChain(alias);

					for (int i = 0; i != certs.Length; i++)
					{
						usedSet.add(certs[i]);
					}
			}

			for (Enumeration en = certs.keys(); en.hasMoreElements();)
			{
				string alias = (string)en.nextElement();

				Certificate cert = engineGetCertificate(alias);

				usedSet.add(cert);
			}

			return usedSet;
		}

		private byte[] calculatePbeMac(ASN1ObjectIdentifier oid, byte[] salt, int itCount, char[] password, bool wrongPkcs12Zero, byte[] org)
		{
			PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);

			Mac mac = helper.createMac(oid.getId());
			mac.init(new PKCS12Key(password, wrongPkcs12Zero), defParams);
			mac.update(PKCSObjectIdentifiers_Fields.data);

			return mac.doFinal();
		}

		public class BCPKCS12KeyStore : PKCS12KeyStoreSpi
		{
			public BCPKCS12KeyStore() : base(PKCS12KeyStoreSpi.getBouncyCastleProvider(), org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC)
			{
			}
		}

		public class BCPKCS12KeyStore3DES : PKCS12KeyStoreSpi
		{
			public BCPKCS12KeyStore3DES() : base(PKCS12KeyStoreSpi.getBouncyCastleProvider(), org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC)
			{
			}
		}

		public class DefPKCS12KeyStore : PKCS12KeyStoreSpi
		{
			public DefPKCS12KeyStore() : base(null, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC)
			{
			}
		}

		public class DefPKCS12KeyStore3DES : PKCS12KeyStoreSpi
		{
			public DefPKCS12KeyStore3DES() : base(null, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC)
			{
			}
		}

		public class IgnoresCaseHashtable
		{
			internal Hashtable orig = new Hashtable();
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
			internal Hashtable keys_Renamed = new Hashtable();

			public virtual void put(string key, object value)
			{
				string lower = (string.ReferenceEquals(key, null)) ? null : Strings.toLowerCase(key);
				string k = (string)keys_Renamed.get(lower);
				if (!string.ReferenceEquals(k, null))
				{
					orig.remove(k);
				}

				keys_Renamed.put(lower, key);
				orig.put(key, value);
			}

			public virtual Enumeration keys()
			{
				return orig.keys();
			}

			public virtual object remove(string alias)
			{
				string k = (string)keys_Renamed.remove(string.ReferenceEquals(alias, null) ? null : Strings.toLowerCase(alias));
				if (string.ReferenceEquals(k, null))
				{
					return null;
				}

				return orig.remove(k);
			}

			public virtual object get(string alias)
			{
				string k = (string)keys_Renamed.get(string.ReferenceEquals(alias, null) ? null : Strings.toLowerCase(alias));
				if (string.ReferenceEquals(k, null))
				{
					return null;
				}

				return orig.get(k);
			}

			public virtual Enumeration elements()
			{
				return orig.elements();
			}
		}

		public class DefaultSecretKeyProvider
		{
			internal readonly Map KEY_SIZES;

			public DefaultSecretKeyProvider()
			{
				Map keySizes = new HashMap();

				keySizes.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));

				keySizes.put(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, Integers.valueOf(192));

				keySizes.put(NISTObjectIdentifiers_Fields.id_aes128_CBC, Integers.valueOf(128));
				keySizes.put(NISTObjectIdentifiers_Fields.id_aes192_CBC, Integers.valueOf(192));
				keySizes.put(NISTObjectIdentifiers_Fields.id_aes256_CBC, Integers.valueOf(256));

				keySizes.put(NTTObjectIdentifiers_Fields.id_camellia128_cbc, Integers.valueOf(128));
				keySizes.put(NTTObjectIdentifiers_Fields.id_camellia192_cbc, Integers.valueOf(192));
				keySizes.put(NTTObjectIdentifiers_Fields.id_camellia256_cbc, Integers.valueOf(256));

				keySizes.put(CryptoProObjectIdentifiers_Fields.gostR28147_gcfb, Integers.valueOf(256));

				KEY_SIZES = Collections.unmodifiableMap(keySizes);
			}

			public virtual int getKeySize(AlgorithmIdentifier algorithmIdentifier)
			{
				// TODO: not all ciphers/oid relationships are this simple.
				int? keySize = (int?)KEY_SIZES.get(algorithmIdentifier.getAlgorithm());

				if (keySize != null)
				{
					return keySize.Value;
				}

				return -1;
			}
		}

		private static Provider provider = null;

		private static Provider getBouncyCastleProvider()
		{
			lock (typeof(PKCS12KeyStoreSpi))
			{
				if (Security.getProvider("BC") != null)
				{
					return Security.getProvider("BC");
				}
				else if (provider == null)
				{
					provider = new BouncyCastleProvider();
				}
        
				return provider;
			}
		}
	}

}