using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.openssl.jcajce
{


	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using EncryptionScheme = org.bouncycastle.asn1.pkcs.EncryptionScheme;
	using KeyDerivationFunc = org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PKCS12KeyWithParameters = org.bouncycastle.jcajce.PKCS12KeyWithParameters;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	public class JceOpenSSLPKCS8EncryptorBuilder
	{
		public static readonly string AES_128_CBC = NISTObjectIdentifiers_Fields.id_aes128_CBC.getId();
		public static readonly string AES_192_CBC = NISTObjectIdentifiers_Fields.id_aes192_CBC.getId();
		public static readonly string AES_256_CBC = NISTObjectIdentifiers_Fields.id_aes256_CBC.getId();

		public static readonly string DES3_CBC = PKCSObjectIdentifiers_Fields.des_EDE3_CBC.getId();

		public static readonly string PBE_SHA1_RC4_128 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4.getId();
		public static readonly string PBE_SHA1_RC4_40 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4.getId();
		public static readonly string PBE_SHA1_3DES = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC.getId();
		public static readonly string PBE_SHA1_2DES = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC.getId();
		public static readonly string PBE_SHA1_RC2_128 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC2_CBC.getId();
		public static readonly string PBE_SHA1_RC2_40 = PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC.getId();

		private JcaJceHelper helper = new DefaultJcaJceHelper();

		private AlgorithmParameters @params;
		private ASN1ObjectIdentifier algOID;
		internal byte[] salt;
		internal int iterationCount;
		private Cipher cipher;
		private SecureRandom random;
		private AlgorithmParameterGenerator paramGen;
		private char[] password;

		private SecretKey key;
		private AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE);

		public JceOpenSSLPKCS8EncryptorBuilder(ASN1ObjectIdentifier algorithm)
		{
			algOID = algorithm;

			this.iterationCount = 2048;
		}

		public virtual JceOpenSSLPKCS8EncryptorBuilder setRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual JceOpenSSLPKCS8EncryptorBuilder setPasssword(char[] password)
		{
			this.password = password;

			return this;
		}

		/// <summary>
		/// Set the PRF to use for key generation. By default this is HmacSHA1.
		/// </summary>
		/// <param name="prf"> algorithm id for PRF.
		/// </param>
		/// <returns> the current builder. </returns>
		public virtual JceOpenSSLPKCS8EncryptorBuilder setPRF(AlgorithmIdentifier prf)
		{
			this.prf = prf;

			return this;
		}

		public virtual JceOpenSSLPKCS8EncryptorBuilder setIterationCount(int iterationCount)
		{
			this.iterationCount = iterationCount;

			return this;
		}

		public virtual JceOpenSSLPKCS8EncryptorBuilder setProvider(string providerName)
		{
			helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JceOpenSSLPKCS8EncryptorBuilder setProvider(Provider provider)
		{
			helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual OutputEncryptor build()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.x509.AlgorithmIdentifier algID;
			AlgorithmIdentifier algID;

			if (random == null)
			{
				random = new SecureRandom();
			}

			try
			{
				this.cipher = helper.createCipher(algOID.getId());

				if (PEMUtilities.isPKCS5Scheme2(algOID))
				{
					this.paramGen = helper.createAlgorithmParameterGenerator(algOID.getId());
				}
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException(algOID + " not available: " + e.Message, e);
			}

			if (PEMUtilities.isPKCS5Scheme2(algOID))
			{
				salt = new byte[PEMUtilities.getSaltSize(prf.getAlgorithm())];

				random.nextBytes(salt);

				@params = paramGen.generateParameters();

				try
				{
					EncryptionScheme scheme = new EncryptionScheme(algOID, ASN1Primitive.fromByteArray(@params.getEncoded()));
					KeyDerivationFunc func = new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, new PBKDF2Params(salt, iterationCount, prf));

					ASN1EncodableVector v = new ASN1EncodableVector();

					v.add(func);
					v.add(scheme);

					algID = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_PBES2, PBES2Parameters.getInstance(new DERSequence(v)));
				}
				catch (IOException e)
				{
					throw new OperatorCreationException(e.Message, e);
				}

				try
				{
					if (PEMUtilities.isHmacSHA1(prf))
					{
						key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, algOID.getId(), password, salt, iterationCount);
					}
					else
					{
						key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, algOID.getId(), password, salt, iterationCount, prf);
					}

					cipher.init(Cipher.ENCRYPT_MODE, key, @params);
				}
				catch (GeneralSecurityException e)
				{
					throw new OperatorCreationException(e.Message, e);
				}
			}
			else if (PEMUtilities.isPKCS12(algOID))
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				salt = new byte[20];

				random.nextBytes(salt);

				v.add(new DEROctetString(salt));
				v.add(new ASN1Integer(iterationCount));

				algID = new AlgorithmIdentifier(algOID, PKCS12PBEParams.getInstance(new DERSequence(v)));

				try
				{
					cipher.init(Cipher.ENCRYPT_MODE, new PKCS12KeyWithParameters(password, salt, iterationCount));
				}
				catch (GeneralSecurityException e)
				{
					throw new OperatorCreationException(e.Message, e);
				}
			}
			else
			{
				throw new OperatorCreationException("unknown algorithm: " + algOID, null);
			}

			return new OutputEncryptorAnonymousInnerClass(this, algID);
		}

		public class OutputEncryptorAnonymousInnerClass : OutputEncryptor
		{
			private readonly JceOpenSSLPKCS8EncryptorBuilder outerInstance;

			private AlgorithmIdentifier algID;

			public OutputEncryptorAnonymousInnerClass(JceOpenSSLPKCS8EncryptorBuilder outerInstance, AlgorithmIdentifier algID)
			{
				this.outerInstance = outerInstance;
				this.algID = algID;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algID;
			}

			public OutputStream getOutputStream(OutputStream encOut)
			{
				return new CipherOutputStream(encOut, outerInstance.cipher);
			}

			public GenericKey getKey()
			{
				return new JceGenericKey(algID, outerInstance.key);
			}
		}
	}

}