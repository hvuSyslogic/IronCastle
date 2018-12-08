using System;

namespace org.bouncycastle.jcajce.provider.keystore.bc
{


	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using PBEParametersGenerator = org.bouncycastle.crypto.PBEParametersGenerator;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using DigestInputStream = org.bouncycastle.crypto.io.DigestInputStream;
	using DigestOutputStream = org.bouncycastle.crypto.io.DigestOutputStream;
	using MacInputStream = org.bouncycastle.crypto.io.MacInputStream;
	using MacOutputStream = org.bouncycastle.crypto.io.MacOutputStream;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using BCKeyStore = org.bouncycastle.jce.interfaces.BCKeyStore;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class BcKeyStoreSpi : KeyStoreSpi, BCKeyStore
	{
		private const int STORE_VERSION = 2;

		private const int STORE_SALT_SIZE = 20;
		private const string STORE_CIPHER = "PBEWithSHAAndTwofish-CBC";

		private const int KEY_SALT_SIZE = 20;
		private const int MIN_ITERATIONS = 1024;

		private const string KEY_CIPHER = "PBEWithSHAAnd3-KeyTripleDES-CBC";

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

		protected internal Hashtable table = new Hashtable();

		protected internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

		protected internal int version;

		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		public BcKeyStoreSpi(int version)
		{
			this.version = version;
		}

		public class StoreEntry
		{
			private readonly BcKeyStoreSpi outerInstance;

			internal int type;
			internal string alias;
			internal object obj;
			internal Certificate[] certChain;
			internal DateTime date = DateTime.Now;

			public StoreEntry(BcKeyStoreSpi outerInstance, string alias, Certificate obj)
			{
				this.outerInstance = outerInstance;
				this.type = CERTIFICATE;
				this.alias = alias;
				this.obj = obj;
				this.certChain = null;
			}

			public StoreEntry(BcKeyStoreSpi outerInstance, string alias, byte[] obj, Certificate[] certChain)
			{
				this.outerInstance = outerInstance;
				this.type = SECRET;
				this.alias = alias;
				this.obj = obj;
				this.certChain = certChain;
			}

			public StoreEntry(BcKeyStoreSpi outerInstance, string alias, Key key, char[] password, Certificate[] certChain)
			{
				this.outerInstance = outerInstance;
				this.type = SEALED;
				this.alias = alias;
				this.certChain = certChain;

				byte[] salt = new byte[KEY_SALT_SIZE];

				outerInstance.random.setSeed(System.currentTimeMillis());
				outerInstance.random.nextBytes(salt);

				int iterationCount = MIN_ITERATIONS + (outerInstance.random.nextInt() & 0x3ff);


				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DataOutputStream dOut = new DataOutputStream(bOut);

				dOut.writeInt(salt.Length);
				dOut.write(salt);
				dOut.writeInt(iterationCount);

				Cipher cipher = outerInstance.makePBECipher(KEY_CIPHER, Cipher.ENCRYPT_MODE, password, salt, iterationCount);
				CipherOutputStream cOut = new CipherOutputStream(dOut, cipher);

				dOut = new DataOutputStream(cOut);

				outerInstance.encodeKey(key, dOut);

				dOut.close();

				obj = bOut.toByteArray();
			}

			public StoreEntry(BcKeyStoreSpi outerInstance, string alias, DateTime date, int type, object obj)
			{
				this.outerInstance = outerInstance;
				this.alias = alias;
				this.date = date;
				this.type = type;
				this.obj = obj;
			}

			public StoreEntry(BcKeyStoreSpi outerInstance, string alias, DateTime date, int type, object obj, Certificate[] certChain)
			{
				this.outerInstance = outerInstance;
				this.alias = alias;
				this.date = date;
				this.type = type;
				this.obj = obj;
				this.certChain = certChain;
			}

			public virtual int getType()
			{
				return type;
			}

			public virtual string getAlias()
			{
				return alias;
			}

			public virtual object getObject()
			{
				return obj;
			}

			public virtual object getObject(char[] password)
			{
				if (password == null || password.Length == 0)
				{
					if (obj is Key)
					{
						return obj;
					}
				}

				if (type == SEALED)
				{
					ByteArrayInputStream bIn = new ByteArrayInputStream((byte[])obj);
					DataInputStream dIn = new DataInputStream(bIn);

					try
					{
						byte[] salt = new byte[dIn.readInt()];

						dIn.readFully(salt);

						int iterationCount = dIn.readInt();

						Cipher cipher = outerInstance.makePBECipher(KEY_CIPHER, Cipher.DECRYPT_MODE, password, salt, iterationCount);

						CipherInputStream cIn = new CipherInputStream(dIn, cipher);

						try
						{
							return outerInstance.decodeKey(new DataInputStream(cIn));
						}
						catch (Exception)
						{
							bIn = new ByteArrayInputStream((byte[])obj);
							dIn = new DataInputStream(bIn);

							salt = new byte[dIn.readInt()];

							dIn.readFully(salt);

							iterationCount = dIn.readInt();

							cipher = outerInstance.makePBECipher("Broken" + KEY_CIPHER, Cipher.DECRYPT_MODE, password, salt, iterationCount);

							cIn = new CipherInputStream(dIn, cipher);

							Key k = null;

							try
							{
								k = outerInstance.decodeKey(new DataInputStream(cIn));
							}
							catch (Exception)
							{
								bIn = new ByteArrayInputStream((byte[])obj);
								dIn = new DataInputStream(bIn);

								salt = new byte[dIn.readInt()];

								dIn.readFully(salt);

								iterationCount = dIn.readInt();

								cipher = outerInstance.makePBECipher("Old" + KEY_CIPHER, Cipher.DECRYPT_MODE, password, salt, iterationCount);

								cIn = new CipherInputStream(dIn, cipher);

								k = outerInstance.decodeKey(new DataInputStream(cIn));
							}

							//
							// reencrypt key with correct cipher.
							//
							if (k != null)
							{
								ByteArrayOutputStream bOut = new ByteArrayOutputStream();
								DataOutputStream dOut = new DataOutputStream(bOut);

								dOut.writeInt(salt.Length);
								dOut.write(salt);
								dOut.writeInt(iterationCount);

								Cipher @out = outerInstance.makePBECipher(KEY_CIPHER, Cipher.ENCRYPT_MODE, password, salt, iterationCount);
								CipherOutputStream cOut = new CipherOutputStream(dOut, @out);

								dOut = new DataOutputStream(cOut);

								outerInstance.encodeKey(k, dOut);

								dOut.close();

								obj = bOut.toByteArray();

								return k;
							}
							else
							{
								throw new UnrecoverableKeyException("no match");
							}
						}
					}
					catch (Exception)
					{
						throw new UnrecoverableKeyException("no match");
					}
				}
				else
				{
					throw new RuntimeException("forget something!");
					// TODO
					// if we get to here key was saved as byte data, which
					// according to the docs means it must be a private key
					// in EncryptedPrivateKeyInfo (PKCS8 format), later...
					//
				}
			}

			public virtual Certificate[] getCertificateChain()
			{
				return certChain;
			}

			public virtual DateTime getDate()
			{
				return date;
			}
		}

		private void encodeCertificate(Certificate cert, DataOutputStream dOut)
		{
			try
			{
				byte[] cEnc = cert.getEncoded();

				dOut.writeUTF(cert.getType());
				dOut.writeInt(cEnc.Length);
				dOut.write(cEnc);
			}
			catch (CertificateEncodingException ex)
			{
				throw new IOException(ex.ToString());
			}
		}

		private Certificate decodeCertificate(DataInputStream dIn)
		{
			string type = dIn.readUTF();
			byte[] cEnc = new byte[dIn.readInt()];

			dIn.readFully(cEnc);

			try
			{
				CertificateFactory cFact = helper.createCertificateFactory(type);
				ByteArrayInputStream bIn = new ByteArrayInputStream(cEnc);

				return cFact.generateCertificate(bIn);
			}
			catch (NoSuchProviderException ex)
			{
				throw new IOException(ex.ToString());
			}
			catch (CertificateException ex)
			{
				throw new IOException(ex.ToString());
			}
		}

		private void encodeKey(Key key, DataOutputStream dOut)
		{
			byte[] enc = key.getEncoded();

			if (key is PrivateKey)
			{
				dOut.write(KEY_PRIVATE);
			}
			else if (key is PublicKey)
			{
				dOut.write(KEY_PUBLIC);
			}
			else
			{
				dOut.write(KEY_SECRET);
			}

			dOut.writeUTF(key.getFormat());
			dOut.writeUTF(key.getAlgorithm());
			dOut.writeInt(enc.Length);
			dOut.write(enc);
		}

		private Key decodeKey(DataInputStream dIn)
		{
			int keyType = dIn.read();
			string format = dIn.readUTF();
			string algorithm = dIn.readUTF();
			byte[] enc = new byte[dIn.readInt()];
			KeySpec spec;

			dIn.readFully(enc);

			if (format.Equals("PKCS#8") || format.Equals("PKCS8"))
			{
				spec = new PKCS8EncodedKeySpec(enc);
			}
			else if (format.Equals("X.509") || format.Equals("X509"))
			{
				spec = new X509EncodedKeySpec(enc);
			}
			else if (format.Equals("RAW"))
			{
				return new SecretKeySpec(enc, algorithm);
			}
			else
			{
				throw new IOException("Key format " + format + " not recognised!");
			}

			try
			{
				switch (keyType)
				{
				case KEY_PRIVATE:
					return BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(enc));
				case KEY_PUBLIC:
					return BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(enc));
				case KEY_SECRET:
					return helper.createSecretKeyFactory(algorithm).generateSecret(spec);
				default:
					throw new IOException("Key type " + keyType + " not recognised!");
				}
			}
			catch (Exception e)
			{
				throw new IOException("Exception creating key: " + e.ToString());
			}
		}

		public virtual Cipher makePBECipher(string algorithm, int mode, char[] password, byte[] salt, int iterationCount)
		{
			try
			{
				PBEKeySpec pbeSpec = new PBEKeySpec(password);
				SecretKeyFactory keyFact = helper.createSecretKeyFactory(algorithm);
				PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);

				Cipher cipher = helper.createCipher(algorithm);

				cipher.init(mode, keyFact.generateSecret(pbeSpec), defParams);

				return cipher;
			}
			catch (Exception e)
			{
				throw new IOException("Error initialising store of key store: " + e);
			}
		}

		public virtual void setRandom(SecureRandom rand)
		{
			this.random = rand;
		}

		public virtual Enumeration engineAliases()
		{
			return table.keys();
		}

		public virtual bool engineContainsAlias(string alias)
		{
			return (table.get(alias) != null);
		}

		public virtual void engineDeleteEntry(string alias)
		{
			object entry = table.get(alias);

			if (entry == null)
			{
				return;
			}

			table.remove(alias);
		}

		public virtual Certificate engineGetCertificate(string alias)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null)
			{
				if (entry.getType() == CERTIFICATE)
				{
					return (Certificate)entry.getObject();
				}
				else
				{
					Certificate[] chain = entry.getCertificateChain();

					if (chain != null)
					{
						return chain[0];
					}
				}
			}

			return null;
		}

		public virtual string engineGetCertificateAlias(Certificate cert)
		{
			Enumeration e = table.elements();
			while (e.hasMoreElements())
			{
				StoreEntry entry = (StoreEntry)e.nextElement();

				if (entry.getObject() is Certificate)
				{
					Certificate c = (Certificate)entry.getObject();

					if (c.Equals(cert))
					{
						return entry.getAlias();
					}
				}
				else
				{
					Certificate[] chain = entry.getCertificateChain();

					if (chain != null && chain[0].Equals(cert))
					{
						return entry.getAlias();
					}
				}
			}

			return null;
		}

		public virtual Certificate[] engineGetCertificateChain(string alias)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null)
			{
				return entry.getCertificateChain();
			}

			return null;
		}

		public virtual DateTime engineGetCreationDate(string alias)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null)
			{
				return entry.getDate();
			}

			return null;
		}

		public virtual Key engineGetKey(string alias, char[] password)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry == null || entry.getType() == CERTIFICATE)
			{
				return null;
			}

			return (Key)entry.getObject(password);
		}

		public virtual bool engineIsCertificateEntry(string alias)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null && entry.getType() == CERTIFICATE)
			{
				return true;
			}

			return false;
		}

		public virtual bool engineIsKeyEntry(string alias)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null && entry.getType() != CERTIFICATE)
			{
				return true;
			}

			return false;
		}

		public virtual void engineSetCertificateEntry(string alias, Certificate cert)
		{
			StoreEntry entry = (StoreEntry)table.get(alias);

			if (entry != null && entry.getType() != CERTIFICATE)
			{
				throw new KeyStoreException("key store already has a key entry with alias " + alias);
			}

			table.put(alias, new StoreEntry(this, alias, cert));
		}

		public virtual void engineSetKeyEntry(string alias, byte[] key, Certificate[] chain)
		{
			table.put(alias, new StoreEntry(this, alias, key, chain));
		}

		public virtual void engineSetKeyEntry(string alias, Key key, char[] password, Certificate[] chain)
		{
			if ((key is PrivateKey) && (chain == null))
			{
				throw new KeyStoreException("no certificate chain for private key");
			}

			try
			{
				table.put(alias, new StoreEntry(this, alias, key, password, chain));
			}
			catch (Exception e)
			{
				throw new KeyStoreException(e.ToString());
			}
		}

		public virtual int engineSize()
		{
			return table.size();
		}

		public virtual void loadStore(InputStream @in)
		{
			DataInputStream dIn = new DataInputStream(@in);
			int type = dIn.read();

			while (type > NULL)
			{
				string alias = dIn.readUTF();
				DateTime date = new DateTime(dIn.readLong());
				int chainLength = dIn.readInt();
				Certificate[] chain = null;

				if (chainLength != 0)
				{
					chain = new Certificate[chainLength];

					for (int i = 0; i != chainLength; i++)
					{
						chain[i] = decodeCertificate(dIn);
					}
				}

				switch (type)
				{
				case CERTIFICATE:
						Certificate cert = decodeCertificate(dIn);

						table.put(alias, new StoreEntry(this, alias, date, CERTIFICATE, cert));
						break;
				case KEY:
						Key key = decodeKey(dIn);
						table.put(alias, new StoreEntry(this, alias, date, KEY, key, chain));
						break;
				case SECRET:
				case SEALED:
						byte[] b = new byte[dIn.readInt()];

						dIn.readFully(b);
						table.put(alias, new StoreEntry(this, alias, date, type, b, chain));
						break;
				default:
						throw new IOException("Unknown object type in store.");
				}

				type = dIn.read();
			}
		}

		public virtual void saveStore(OutputStream @out)
		{
			Enumeration e = table.elements();
			DataOutputStream dOut = new DataOutputStream(@out);

			while (e.hasMoreElements())
			{
				StoreEntry entry = (StoreEntry)e.nextElement();

				dOut.write(entry.getType());
				dOut.writeUTF(entry.getAlias());
				dOut.writeLong(entry.getDate().Ticks);

				Certificate[] chain = entry.getCertificateChain();
				if (chain == null)
				{
					dOut.writeInt(0);
				}
				else
				{
					dOut.writeInt(chain.Length);
					for (int i = 0; i != chain.Length; i++)
					{
						encodeCertificate(chain[i], dOut);
					}
				}

				switch (entry.getType())
				{
				case CERTIFICATE:
						encodeCertificate((Certificate)entry.getObject(), dOut);
						break;
				case KEY:
						encodeKey((Key)entry.getObject(), dOut);
						break;
				case SEALED:
				case SECRET:
						byte[] b = (byte[])entry.getObject();

						dOut.writeInt(b.Length);
						dOut.write(b);
						break;
				default:
						throw new IOException("Unknown object type in store.");
				}
			}

			dOut.write(NULL);
		}

		public virtual void engineLoad(InputStream stream, char[] password)
		{
			table.clear();

			if (stream == null) // just initialising
			{
				return;
			}

			DataInputStream dIn = new DataInputStream(stream);
			int version = dIn.readInt();

			if (version != STORE_VERSION)
			{
				if (version != 0 && version != 1)
				{
					throw new IOException("Wrong version of key store.");
				}
			}

			int saltLength = dIn.readInt();
			if (saltLength <= 0)
			{
				throw new IOException("Invalid salt detected");
			}

			byte[] salt = new byte[saltLength];

			dIn.readFully(salt);

			int iterationCount = dIn.readInt();

			//
			// we only do an integrity check if the password is provided.
			//
			HMac hMac = new HMac(new SHA1Digest());
			if (password != null && password.Length != 0)
			{
				byte[] passKey = PBEParametersGenerator.PKCS12PasswordToBytes(password);

				PBEParametersGenerator pbeGen = new PKCS12ParametersGenerator(new SHA1Digest());
				pbeGen.init(passKey, salt, iterationCount);

				CipherParameters macParams;

				if (version != 2)
				{
					macParams = pbeGen.generateDerivedMacParameters(hMac.getMacSize());
				}
				else
				{
					macParams = pbeGen.generateDerivedMacParameters(hMac.getMacSize() * 8);
				}

				Arrays.fill(passKey, (byte)0);

				hMac.init(macParams);
				MacInputStream mIn = new MacInputStream(dIn, hMac);

				loadStore(mIn);

				// Finalise our mac calculation
				byte[] mac = new byte[hMac.getMacSize()];
				hMac.doFinal(mac, 0);

				// TODO Should this actually be reading the remainder of the stream?
				// Read the original mac from the stream
				byte[] oldMac = new byte[hMac.getMacSize()];
				dIn.readFully(oldMac);

				if (!Arrays.constantTimeAreEqual(mac, oldMac))
				{
					table.clear();
					throw new IOException("KeyStore integrity check failed.");
				}
			}
			else
			{
				loadStore(dIn);

				// TODO Should this actually be reading the remainder of the stream?
				// Parse the original mac from the stream too
				byte[] oldMac = new byte[hMac.getMacSize()];
				dIn.readFully(oldMac);
			}
		}


		public virtual void engineStore(OutputStream stream, char[] password)
		{
			DataOutputStream dOut = new DataOutputStream(stream);
			byte[] salt = new byte[STORE_SALT_SIZE];
			int iterationCount = MIN_ITERATIONS + (random.nextInt() & 0x3ff);

			random.nextBytes(salt);

			dOut.writeInt(version);
			dOut.writeInt(salt.Length);
			dOut.write(salt);
			dOut.writeInt(iterationCount);

			HMac hMac = new HMac(new SHA1Digest());
			MacOutputStream mOut = new MacOutputStream(hMac);
			PBEParametersGenerator pbeGen = new PKCS12ParametersGenerator(new SHA1Digest());
			byte[] passKey = PBEParametersGenerator.PKCS12PasswordToBytes(password);

			pbeGen.init(passKey, salt, iterationCount);

			if (version < 2)
			{
				hMac.init(pbeGen.generateDerivedMacParameters(hMac.getMacSize()));
			}
			else
			{
				hMac.init(pbeGen.generateDerivedMacParameters(hMac.getMacSize() * 8));
			}

			for (int i = 0; i != passKey.Length; i++)
			{
				passKey[i] = 0;
			}

			saveStore(new TeeOutputStream(dOut, mOut));

			byte[] mac = new byte[hMac.getMacSize()];

			hMac.doFinal(mac, 0);

			dOut.write(mac);

			dOut.close();
		}

		/// <summary>
		/// the BouncyCastle store. This wont work with the key tool as the
		/// store is stored encrypted on disk, so the password is mandatory,
		/// however if you hard drive is in a bad part of town and you absolutely,
		/// positively, don't want nobody peeking at your things, this is the
		/// one to use, no problem! After all in a Bouncy Castle nothing can
		/// touch you.
		/// 
		/// Also referred to by the alias UBER.
		/// </summary>
		public class BouncyCastleStore : BcKeyStoreSpi
		{
			public BouncyCastleStore() : base(1)
			{
			}

			public override void engineLoad(InputStream stream, char[] password)
			{
				table.clear();

				if (stream == null) // just initialising
				{
					return;
				}

				DataInputStream dIn = new DataInputStream(stream);
				int version = dIn.readInt();

				if (version != STORE_VERSION)
				{
					if (version != 0 && version != 1)
					{
						throw new IOException("Wrong version of key store.");
					}
				}

				byte[] salt = new byte[dIn.readInt()];

				if (salt.Length != STORE_SALT_SIZE)
				{
					throw new IOException("Key store corrupted.");
				}

				dIn.readFully(salt);

				int iterationCount = dIn.readInt();

				if ((iterationCount < 0) || (iterationCount > (MIN_ITERATIONS << 6)))
				{
					throw new IOException("Key store corrupted.");
				}

				string cipherAlg;
				if (version == 0)
				{
					cipherAlg = "Old" + STORE_CIPHER;
				}
				else
				{
					cipherAlg = STORE_CIPHER;
				}

				Cipher cipher = this.makePBECipher(cipherAlg, Cipher.DECRYPT_MODE, password, salt, iterationCount);
				CipherInputStream cIn = new CipherInputStream(dIn, cipher);

				Digest dig = new SHA1Digest();
				DigestInputStream dgIn = new DigestInputStream(cIn, dig);

				this.loadStore(dgIn);

				// Finalise our digest calculation
				byte[] hash = new byte[dig.getDigestSize()];
				dig.doFinal(hash, 0);

				// TODO Should this actually be reading the remainder of the stream?
				// Read the original digest from the stream
				byte[] oldHash = new byte[dig.getDigestSize()];
				Streams.readFully(cIn, oldHash);

				if (!Arrays.constantTimeAreEqual(hash, oldHash))
				{
					table.clear();
					throw new IOException("KeyStore integrity check failed.");
				}
			}

			public override void engineStore(OutputStream stream, char[] password)
			{
				Cipher cipher;
				DataOutputStream dOut = new DataOutputStream(stream);
				byte[] salt = new byte[STORE_SALT_SIZE];
				int iterationCount = MIN_ITERATIONS + (random.nextInt() & 0x3ff);

				random.nextBytes(salt);

				dOut.writeInt(version);
				dOut.writeInt(salt.Length);
				dOut.write(salt);
				dOut.writeInt(iterationCount);

				cipher = this.makePBECipher(STORE_CIPHER, Cipher.ENCRYPT_MODE, password, salt, iterationCount);

				CipherOutputStream cOut = new CipherOutputStream(dOut, cipher);
				DigestOutputStream dgOut = new DigestOutputStream(new SHA1Digest());

				this.saveStore(new TeeOutputStream(cOut, dgOut));

				byte[] dig = dgOut.getDigest();

				cOut.write(dig);

				cOut.close();
			}
		}

		public class Std : BcKeyStoreSpi
		{
			public Std() : base(STORE_VERSION)
			{
			}
		}

		public class Version1 : BcKeyStoreSpi
		{
			public Version1() : base(1)
			{
			}
		}
	}

}