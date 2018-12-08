using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.misc;

using System;

namespace org.bouncycastle.pkcs.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using GOST28147Parameters = org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using ScryptParams = org.bouncycastle.asn1.misc.ScryptParams;
	using PBEParameter = org.bouncycastle.asn1.pkcs.PBEParameter;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PasswordConverter = org.bouncycastle.crypto.PasswordConverter;
	using PBKDF1Key = org.bouncycastle.jcajce.PBKDF1Key;
	using PKCS12KeyWithParameters = org.bouncycastle.jcajce.PKCS12KeyWithParameters;
	using GOST28147ParameterSpec = org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
	using PBKDF2KeySpec = org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
	using ScryptKeySpec = org.bouncycastle.jcajce.spec.ScryptKeySpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;

	public class JcePKCSPBEInputDecryptorProviderBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();
		private bool wrongPKCS12Zero = false;
		private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;

		public JcePKCSPBEInputDecryptorProviderBuilder()
		{
		}

		public virtual JcePKCSPBEInputDecryptorProviderBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcePKCSPBEInputDecryptorProviderBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcePKCSPBEInputDecryptorProviderBuilder setTryWrongPKCS12Zero(bool tryWrong)
		{
			this.wrongPKCS12Zero = tryWrong;

			return this;
		}

		/// <summary>
		/// Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
		/// handle PKCS5 decryption.
		/// </summary>
		/// <param name="keySizeProvider">  a provider of integer secret key sizes.
		/// </param>
		/// <returns> the current builder. </returns>
		public virtual JcePKCSPBEInputDecryptorProviderBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
		{
			this.keySizeProvider = keySizeProvider;

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptorProvider build(final char[] password)
		public virtual InputDecryptorProvider build(char[] password)
		{
			return new InputDecryptorProviderAnonymousInnerClass(this, password);
		}

		public class InputDecryptorProviderAnonymousInnerClass : InputDecryptorProvider
		{
			private readonly JcePKCSPBEInputDecryptorProviderBuilder outerInstance;

			private char[] password;

			public InputDecryptorProviderAnonymousInnerClass(JcePKCSPBEInputDecryptorProviderBuilder outerInstance, char[] password)
			{
				this.outerInstance = outerInstance;
				this.password = password;
			}

			private Cipher cipher;
			private AlgorithmIdentifier encryptionAlg;

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptor get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmIdentifier) throws org.bouncycastle.operator.OperatorCreationException
			public InputDecryptor get(AlgorithmIdentifier algorithmIdentifier)
			{
				SecretKey key;
				ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

				try
				{
					if (algorithm.on(PKCSObjectIdentifiers_Fields.pkcs_12PbeIds))
					{
						PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

						cipher = outerInstance.helper.createCipher(algorithm.getId());

						cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, outerInstance.wrongPKCS12Zero, pbeParams.getIV(), pbeParams.getIterations().intValue()));

						encryptionAlg = algorithmIdentifier;
					}
					else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.id_PBES2))
					{
						PBES2Parameters alg = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());

						if (MiscObjectIdentifiers_Fields.id_scrypt.Equals(alg.getKeyDerivationFunc().getAlgorithm()))
						{
							ScryptParams @params = ScryptParams.getInstance(alg.getKeyDerivationFunc().getParameters());
							AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

							SecretKeyFactory keyFact = outerInstance.helper.createSecretKeyFactory("SCRYPT");

							key = keyFact.generateSecret(new ScryptKeySpec(password, @params.getSalt(), @params.getCostParameter().intValue(), @params.getBlockSize().intValue(), @params.getParallelizationParameter().intValue(), outerInstance.keySizeProvider.getKeySize(encScheme)));
						}
						else
						{
							SecretKeyFactory keyFact = outerInstance.helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
							PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
							AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

							if (func.isDefaultPrf())
							{
								key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), func.getIterationCount().intValue(), outerInstance.keySizeProvider.getKeySize(encScheme)));
							}
							else
							{
								key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), func.getIterationCount().intValue(), outerInstance.keySizeProvider.getKeySize(encScheme), func.getPrf()));
							}
						}

						cipher = outerInstance.helper.createCipher(alg.getEncryptionScheme().getAlgorithm().getId());

						encryptionAlg = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

						ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
						if (encParams is ASN1OctetString)
						{
							cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
						}
						else
						{
							// TODO: at the moment it's just GOST, but...
							GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

							cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
						}
					}
					else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithMD5AndDES_CBC) || algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithSHA1AndDES_CBC))
					{
						PBEParameter pbeParams = PBEParameter.getInstance(algorithmIdentifier.getParameters());

						cipher = outerInstance.helper.createCipher(algorithm.getId());

						cipher.init(Cipher.DECRYPT_MODE, new PBKDF1Key(password, PasswordConverter.ASCII), new PBEParameterSpec(pbeParams.getSalt(), pbeParams.getIterationCount().intValue()));
					}
					else
					{
						throw new OperatorCreationException("unable to create InputDecryptor: algorithm " + algorithm + " unknown.");
					}
				}
				catch (Exception e)
				{
					throw new OperatorCreationException("unable to create InputDecryptor: " + e.Message, e);
				}

				return new InputDecryptorAnonymousInnerClass(this);
			}

			public class InputDecryptorAnonymousInnerClass : InputDecryptor
			{
				private readonly InputDecryptorProviderAnonymousInnerClass outerInstance;

				public InputDecryptorAnonymousInnerClass(InputDecryptorProviderAnonymousInnerClass outerInstance)
				{
					this.outerInstance = outerInstance;
				}

				public AlgorithmIdentifier getAlgorithmIdentifier()
				{
					return encryptionAlg;
				}

				public InputStream getInputStream(InputStream input)
				{
					return new CipherInputStream(input, cipher);
				}
			}
		}
	}

}