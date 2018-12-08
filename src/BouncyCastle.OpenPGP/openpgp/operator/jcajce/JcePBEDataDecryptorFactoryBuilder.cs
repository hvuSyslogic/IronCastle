using System;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	/// <summary>
	/// Builder for <seealso cref="PBEDataDecryptorFactory"/> instances that obtain cryptographic primitives using
	/// the JCE API.
	/// </summary>
	public class JcePBEDataDecryptorFactoryBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private PGPDigestCalculatorProvider calculatorProvider;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="calculatorProvider">   a digest calculator provider to provide calculators to support the key generation calculation required. </param>
		public JcePBEDataDecryptorFactoryBuilder(PGPDigestCalculatorProvider calculatorProvider)
		{
			this.calculatorProvider = calculatorProvider;
		}

		/// <summary>
		/// Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
		/// </summary>
		/// <param name="provider">  provider object for cryptographic primitives. </param>
		/// <returns>  the current builder. </returns>
		public virtual JcePBEDataDecryptorFactoryBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		/// <summary>
		/// Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
		/// </summary>
		/// <param name="providerName">  the name of the provider to reference for cryptographic primitives. </param>
		/// <returns>  the current builder. </returns>
		public virtual JcePBEDataDecryptorFactoryBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		/// <summary>
		/// Construct a <seealso cref="PBEDataDecryptorFactory"/> to use to decrypt PBE encrypted data.
		/// </summary>
		/// <param name="passPhrase"> the pass phrase to use to generate keys in the resulting factory. </param>
		/// <returns> a decryptor factory that can be used to generate PBE keys. </returns>
		public virtual PBEDataDecryptorFactory build(char[] passPhrase)
		{
			 return new PBEDataDecryptorFactoryAnonymousInnerClass(this, passPhrase, calculatorProvider);
		}

		public class PBEDataDecryptorFactoryAnonymousInnerClass : PBEDataDecryptorFactory
		{
			private readonly JcePBEDataDecryptorFactoryBuilder outerInstance;

			public PBEDataDecryptorFactoryAnonymousInnerClass(JcePBEDataDecryptorFactoryBuilder outerInstance, char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider) : base(passPhrase, calculatorProvider)
			{
				this.outerInstance = outerInstance;
			}

			public override byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
			{
				try
				{
					if (secKeyData != null && secKeyData.Length > 0)
					{
						string cipherName = PGPUtil.getSymmetricCipherName(keyAlgorithm);
						Cipher keyCipher = outerInstance.helper.createCipher(cipherName + "/CFB/NoPadding");

						keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, cipherName), new IvParameterSpec(new byte[keyCipher.getBlockSize()]));

						return keyCipher.doFinal(secKeyData);
					}
					else
					{
						byte[] keyBytes = new byte[key.Length + 1];

						keyBytes[0] = (byte)keyAlgorithm;
						JavaSystem.arraycopy(key, 0, keyBytes, 1, key.Length);

						return keyBytes;
					}
				}
				catch (Exception e)
				{
					throw new PGPException("Exception recovering session info", e);
				}
			}

			public override PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
			{
				return outerInstance.helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
			}
		}
	}

}