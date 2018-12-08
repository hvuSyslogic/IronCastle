using System;

namespace org.bouncycastle.@operator.jcajce
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using GOST28147Parameters = org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GOST28147ParameterSpec = org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A generic decryptor provider for IETF style algorithms.
	/// </summary>
	public class JceInputDecryptorProviderBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		public JceInputDecryptorProviderBuilder()
		{
		}

		public virtual JceInputDecryptorProviderBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JceInputDecryptorProviderBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		/// <summary>
		/// Build a decryptor provider which will use the passed in bytes for the symmetric key.
		/// </summary>
		/// <param name="keyBytes"> bytes representing the key to use. </param>
		/// <returns> an decryptor provider. </returns>
		public virtual InputDecryptorProvider build(byte[] keyBytes)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] encKeyBytes = org.bouncycastle.util.Arrays.clone(keyBytes);
			byte[] encKeyBytes = Arrays.clone(keyBytes);

			return new InputDecryptorProviderAnonymousInnerClass(this, encKeyBytes);
		}

		public class InputDecryptorProviderAnonymousInnerClass : InputDecryptorProvider
		{
			private readonly JceInputDecryptorProviderBuilder outerInstance;

			private byte[] encKeyBytes;

			public InputDecryptorProviderAnonymousInnerClass(JceInputDecryptorProviderBuilder outerInstance, byte[] encKeyBytes)
			{
				this.outerInstance = outerInstance;
				this.encKeyBytes = encKeyBytes;
			}

			private Cipher cipher;
			private AlgorithmIdentifier encryptionAlg;

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptor get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmIdentifier) throws org.bouncycastle.operator.OperatorCreationException
			public InputDecryptor get(AlgorithmIdentifier algorithmIdentifier)
			{
				encryptionAlg = algorithmIdentifier;

				ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

				try
				{
					cipher = outerInstance.helper.createCipher(algorithm.getId());
					SecretKey key = new SecretKeySpec(encKeyBytes, algorithm.getId());

					ASN1Encodable encParams = algorithmIdentifier.getParameters();

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