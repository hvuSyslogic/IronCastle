namespace org.bouncycastle.openssl.jcajce
{


	using EncryptionScheme = org.bouncycastle.asn1.pkcs.EncryptionScheme;
	using KeyDerivationFunc = org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
	using PBEParameter = org.bouncycastle.asn1.pkcs.PBEParameter;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CharToByteConverter = org.bouncycastle.crypto.CharToByteConverter;
	using PBKDF1KeyWithParameters = org.bouncycastle.jcajce.PBKDF1KeyWithParameters;
	using PKCS12KeyWithParameters = org.bouncycastle.jcajce.PKCS12KeyWithParameters;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// DecryptorProviderBuilder for producing DecryptorProvider for use with PKCS8EncryptedPrivateKeyInfo.
	/// </summary>
	public class JceOpenSSLPKCS8DecryptorProviderBuilder
	{
		private JcaJceHelper helper;

		public JceOpenSSLPKCS8DecryptorProviderBuilder()
		{
			helper = new DefaultJcaJceHelper();
		}

		public virtual JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(string providerName)
		{
			helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(Provider provider)
		{
			helper = new ProviderJcaJceHelper(provider);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptorProvider build(final char[] password) throws org.bouncycastle.operator.OperatorCreationException
		public virtual InputDecryptorProvider build(char[] password)
		{
			return new InputDecryptorProviderAnonymousInnerClass(this, password);
		}

		public class InputDecryptorProviderAnonymousInnerClass : InputDecryptorProvider
		{
			private readonly JceOpenSSLPKCS8DecryptorProviderBuilder outerInstance;

			private char[] password;

			public InputDecryptorProviderAnonymousInnerClass(JceOpenSSLPKCS8DecryptorProviderBuilder outerInstance, char[] password)
			{
				this.outerInstance = outerInstance;
				this.password = password;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptor get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm) throws org.bouncycastle.operator.OperatorCreationException
			public InputDecryptor get(AlgorithmIdentifier algorithm)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher cipher;
				Cipher cipher;

				try
				{
					if (PEMUtilities.isPKCS5Scheme2(algorithm.getAlgorithm()))
					{
						PBES2Parameters @params = PBES2Parameters.getInstance(algorithm.getParameters());
						KeyDerivationFunc func = @params.getKeyDerivationFunc();
						EncryptionScheme scheme = @params.getEncryptionScheme();
						PBKDF2Params defParams = (PBKDF2Params)func.getParameters();

						int iterationCount = defParams.getIterationCount().intValue();
						byte[] salt = defParams.getSalt();

						string oid = scheme.getAlgorithm().getId();

						SecretKey key;

						if (PEMUtilities.isHmacSHA1(defParams.getPrf()))
						{
							key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(outerInstance.helper, oid, password, salt, iterationCount);
						}
						else
						{
							key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(outerInstance.helper, oid, password, salt, iterationCount, defParams.getPrf());
						}

						cipher = outerInstance.helper.createCipher(oid);
						AlgorithmParameters algParams = outerInstance.helper.createAlgorithmParameters(oid);

						algParams.init(scheme.getParameters().toASN1Primitive().getEncoded());

						cipher.init(Cipher.DECRYPT_MODE, key, algParams);
					}
					else if (PEMUtilities.isPKCS12(algorithm.getAlgorithm()))
					{
						PKCS12PBEParams @params = PKCS12PBEParams.getInstance(algorithm.getParameters());

						cipher = outerInstance.helper.createCipher(algorithm.getAlgorithm().getId());

						cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, @params.getIV(), @params.getIterations().intValue()));
					}
					else if (PEMUtilities.isPKCS5Scheme1(algorithm.getAlgorithm()))
					{
						PBEParameter @params = PBEParameter.getInstance(algorithm.getParameters());

						cipher = outerInstance.helper.createCipher(algorithm.getAlgorithm().getId());

						cipher.init(Cipher.DECRYPT_MODE, new PBKDF1KeyWithParameters(password, new CharToByteConverterAnonymousInnerClass(this)
					   , @params.getSalt(), @params.getIterationCount().intValue()));
					}
					else
					{
						throw new PEMException("Unknown algorithm: " + algorithm.getAlgorithm());
					}

					return new InputDecryptorAnonymousInnerClass(this, algorithm, cipher);
				}
				catch (IOException e)
				{
					throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.Message, e);
				}
				catch (GeneralSecurityException e)
				{
					throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.Message, e);
				}
			};

			public class CharToByteConverterAnonymousInnerClass : CharToByteConverter
			{
				private readonly InputDecryptorProviderAnonymousInnerClass outerInstance;

				public CharToByteConverterAnonymousInnerClass(InputDecryptorProviderAnonymousInnerClass outerInstance)
				{
					this.outerInstance = outerInstance;
				}

				public string getType()
				{
					return "ASCII";
				}

				public byte[] convert(char[] password)
				{
					return Strings.toByteArray(password); // just drop hi-order byte.
				}
			}

			public class InputDecryptorAnonymousInnerClass : InputDecryptor
			{
				private readonly InputDecryptorProviderAnonymousInnerClass outerInstance;

				private AlgorithmIdentifier algorithm;
				private Cipher cipher;

				public InputDecryptorAnonymousInnerClass(InputDecryptorProviderAnonymousInnerClass outerInstance, AlgorithmIdentifier algorithm, Cipher cipher)
				{
					this.outerInstance = outerInstance;
					this.algorithm = algorithm;
					this.cipher = cipher;
				}

				public AlgorithmIdentifier getAlgorithmIdentifier()
				{
					return algorithm;
				}

				public InputStream getInputStream(InputStream encIn)
				{
					return new CipherInputStream(encIn, cipher);
				}
			}
		}
	}

}