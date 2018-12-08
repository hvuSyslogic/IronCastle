using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.misc;
using org.bouncycastle.asn1.bc;

using System;

namespace org.bouncycastle.pkcs.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using BCObjectIdentifiers = org.bouncycastle.asn1.bc.BCObjectIdentifiers;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using ScryptParams = org.bouncycastle.asn1.misc.ScryptParams;
	using EncryptionScheme = org.bouncycastle.asn1.pkcs.EncryptionScheme;
	using KeyDerivationFunc = org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PBKDF2Config = org.bouncycastle.crypto.util.PBKDF2Config;
	using PBKDFConfig = org.bouncycastle.crypto.util.PBKDFConfig;
	using ScryptConfig = org.bouncycastle.crypto.util.ScryptConfig;
	using PKCS12KeyWithParameters = org.bouncycastle.jcajce.PKCS12KeyWithParameters;
	using ScryptKeySpec = org.bouncycastle.jcajce.spec.ScryptKeySpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;

	public class JcePKCSPBEOutputEncryptorBuilder
	{
		private readonly PBKDFConfig pbkdf;

		private JcaJceHelper helper = new DefaultJcaJceHelper();
		private ASN1ObjectIdentifier algorithm;
		private ASN1ObjectIdentifier keyEncAlgorithm;
		private SecureRandom random;
		private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;
		private int iterationCount = 1024;
		private PBKDF2Config.Builder pbkdfBuilder = new PBKDF2Config.Builder();

		public JcePKCSPBEOutputEncryptorBuilder(ASN1ObjectIdentifier keyEncryptionAlg)
		{
			this.pbkdf = null;
			if (isPKCS12(keyEncryptionAlg))
			{
				this.algorithm = keyEncryptionAlg;
				this.keyEncAlgorithm = keyEncryptionAlg;
			}
			else
			{
				this.algorithm = PKCSObjectIdentifiers_Fields.id_PBES2;
				this.keyEncAlgorithm = keyEncryptionAlg;
			}
		}

		/// <summary>
		/// Constructor allowing different derivation functions such as PBKDF2 and scrypt.
		/// </summary>
		/// <param name="pbkdfAlgorithm"> key derivation algorithm definition to use. </param>
		/// <param name="keyEncryptionAlg"> encryption algorithm to apply the derived key with. </param>
		public JcePKCSPBEOutputEncryptorBuilder(PBKDFConfig pbkdfAlgorithm, ASN1ObjectIdentifier keyEncryptionAlg)
		{
			this.algorithm = PKCSObjectIdentifiers_Fields.id_PBES2;
			this.pbkdf = pbkdfAlgorithm;
			this.keyEncAlgorithm = keyEncryptionAlg;
		}

		public virtual JcePKCSPBEOutputEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePKCSPBEOutputEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcePKCSPBEOutputEncryptorBuilder setRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
		/// handle PKCS5 decryption.
		/// </summary>
		/// <param name="keySizeProvider"> a provider of integer secret key sizes. </param>
		/// <returns> the current builder. </returns>
		public virtual JcePKCSPBEOutputEncryptorBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
		{
			this.keySizeProvider = keySizeProvider;

			return this;
		}

		/// <summary>
		/// Set the PRF to use for key generation. By default this is HmacSHA1.
		/// </summary>
		/// <param name="prf"> algorithm id for PRF. </param>
		/// <returns> the current builder. </returns>
		/// <exception cref="IllegalStateException"> if this builder was intialised with a PBKDFDef </exception>
		public virtual JcePKCSPBEOutputEncryptorBuilder setPRF(AlgorithmIdentifier prf)
		{
			if (pbkdf != null)
			{
				throw new IllegalStateException("set PRF count using PBKDFDef");
			}
			this.pbkdfBuilder.withPRF(prf);

			return this;
		}

		/// <summary>
		/// Set the iteration count for the PBE calculation.
		/// </summary>
		/// <param name="iterationCount"> the iteration count to apply to the key creation. </param>
		/// <returns> the current builder. </returns>
		/// <exception cref="IllegalStateException"> if this builder was intialised with a PBKDFDef </exception>
		public virtual JcePKCSPBEOutputEncryptorBuilder setIterationCount(int iterationCount)
		{
			if (pbkdf != null)
			{
				throw new IllegalStateException("set iteration count using PBKDFDef");
			}
			this.iterationCount = iterationCount;
			this.pbkdfBuilder.withIterationCount(iterationCount);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.OutputEncryptor build(final char[] password) throws org.bouncycastle.operator.OperatorCreationException
		public virtual OutputEncryptor build(char[] password)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher cipher;
			Cipher cipher;
			SecretKey key;

			if (random == null)
			{
				random = new SecureRandom();
			}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.x509.AlgorithmIdentifier encryptionAlg;
			AlgorithmIdentifier encryptionAlg;

			try
			{
				if (isPKCS12(algorithm))
				{
					byte[] salt = new byte[20];

					random.nextBytes(salt);

					cipher = helper.createCipher(algorithm.getId());

					cipher.init(Cipher.ENCRYPT_MODE, new PKCS12KeyWithParameters(password, salt, iterationCount));

					encryptionAlg = new AlgorithmIdentifier(algorithm, new PKCS12PBEParams(salt, iterationCount));
				}
				else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.id_PBES2))
				{
					PBKDFConfig pbkDef = (pbkdf == null) ? pbkdfBuilder.build() : pbkdf;

					if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(pbkDef.getAlgorithm()))
					{
						ScryptConfig skdf = (ScryptConfig)pbkDef;

						byte[] salt = new byte[skdf.getSaltLength()];

						random.nextBytes(salt);

						ScryptParams @params = new ScryptParams(salt, skdf.getCostParameter(), skdf.getBlockSize(), skdf.getParallelizationParameter());

						SecretKeyFactory keyFact = helper.createSecretKeyFactory("SCRYPT");

						key = keyFact.generateSecret(new ScryptKeySpec(password, salt, skdf.getCostParameter(), skdf.getBlockSize(), skdf.getParallelizationParameter(), keySizeProvider.getKeySize(new AlgorithmIdentifier(keyEncAlgorithm))));

						cipher = helper.createCipher(keyEncAlgorithm.getId());

						cipher.init(Cipher.ENCRYPT_MODE, key, random);

						PBES2Parameters algParams = new PBES2Parameters(new KeyDerivationFunc(MiscObjectIdentifiers_Fields.id_scrypt, @params), new EncryptionScheme(keyEncAlgorithm, ASN1Primitive.fromByteArray(cipher.getParameters().getEncoded())));

						encryptionAlg = new AlgorithmIdentifier(algorithm, algParams);
					}
					else
					{
						PBKDF2Config pkdf = (PBKDF2Config)pbkDef;

						byte[] salt = new byte[pkdf.getSaltLength()];

						random.nextBytes(salt);

						SecretKeyFactory keyFact = helper.createSecretKeyFactory(JceUtils.getAlgorithm(pkdf.getPRF().getAlgorithm()));

						key = keyFact.generateSecret(new PBEKeySpec(password, salt, pkdf.getIterationCount(), keySizeProvider.getKeySize(new AlgorithmIdentifier(keyEncAlgorithm))));

						cipher = helper.createCipher(keyEncAlgorithm.getId());

						cipher.init(Cipher.ENCRYPT_MODE, key, random);

						PBES2Parameters algParams = new PBES2Parameters(new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, new PBKDF2Params(salt, pkdf.getIterationCount(), pkdf.getPRF())), new EncryptionScheme(keyEncAlgorithm, ASN1Primitive.fromByteArray(cipher.getParameters().getEncoded())));

						encryptionAlg = new AlgorithmIdentifier(algorithm, algParams);
					}
				}
				else
				{
					throw new OperatorCreationException("unrecognised algorithm");
				}

				return new OutputEncryptorAnonymousInnerClass(this, password, cipher, encryptionAlg);
			}
			catch (Exception e)
			{
				throw new OperatorCreationException("unable to create OutputEncryptor: " + e.Message, e);
			}
		}

		public class OutputEncryptorAnonymousInnerClass : OutputEncryptor
		{
			private readonly JcePKCSPBEOutputEncryptorBuilder outerInstance;

			private char[] password;
			private Cipher cipher;
			private AlgorithmIdentifier encryptionAlg;

			public OutputEncryptorAnonymousInnerClass(JcePKCSPBEOutputEncryptorBuilder outerInstance, char[] password, Cipher cipher, AlgorithmIdentifier encryptionAlg)
			{
				this.outerInstance = outerInstance;
				this.password = password;
				this.cipher = cipher;
				this.encryptionAlg = encryptionAlg;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return encryptionAlg;
			}

			public OutputStream getOutputStream(OutputStream @out)
			{
				return new CipherOutputStream(@out, cipher);
			}

			public GenericKey getKey()
			{
				if (outerInstance.isPKCS12(encryptionAlg.getAlgorithm()))
				{
					return new GenericKey(encryptionAlg, PKCS12PasswordToBytes(password));
				}
				else
				{
					return new GenericKey(encryptionAlg, PKCS5PasswordToBytes(password));
				}
			}
		}

		private bool isPKCS12(ASN1ObjectIdentifier algorithm)
		{
			return algorithm.on(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds) || algorithm.on(BCObjectIdentifiers_Fields.bc_pbe_sha1_pkcs12) || algorithm.on(BCObjectIdentifiers_Fields.bc_pbe_sha256_pkcs12);
		}

		/// <summary>
		/// converts a password to a byte array according to the scheme in
		/// PKCS5 (ascii, no padding)
		/// </summary>
		/// <param name="password"> a character array representing the password. </param>
		/// <returns> a byte array representing the password. </returns>
		private static byte[] PKCS5PasswordToBytes(char[] password)
		{
			if (password != null)
			{
				byte[] bytes = new byte[password.Length];

				for (int i = 0; i != bytes.Length; i++)
				{
					bytes[i] = (byte)password[i];
				}

				return bytes;
			}
			else
			{
				return new byte[0];
			}
		}

		/// <summary>
		/// converts a password to a byte array according to the scheme in
		/// PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
		/// </summary>
		/// <param name="password"> a character array representing the password. </param>
		/// <returns> a byte array representing the password. </returns>
		private static byte[] PKCS12PasswordToBytes(char[] password)
		{
			if (password != null && password.Length > 0)
			{
				// +1 for extra 2 pad bytes.
				byte[] bytes = new byte[(password.Length + 1) * 2];

				for (int i = 0; i != password.Length; i++)
				{
					bytes[i * 2] = (byte)((int)((uint)password[i] >> 8));
					bytes[i * 2 + 1] = (byte)password[i];
				}

				return bytes;
			}
			else
			{
				return new byte[0];
			}
		}
	}

}