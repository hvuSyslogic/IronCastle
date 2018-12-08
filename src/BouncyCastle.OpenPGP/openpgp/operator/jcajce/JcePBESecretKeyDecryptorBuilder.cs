namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePBESecretKeyDecryptorBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private PGPDigestCalculatorProvider calculatorProvider;

		private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;

		public JcePBESecretKeyDecryptorBuilder()
		{
			this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
		}

		public JcePBESecretKeyDecryptorBuilder(PGPDigestCalculatorProvider calculatorProvider)
		{
			this.calculatorProvider = calculatorProvider;
		}

		public virtual JcePBESecretKeyDecryptorBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			if (calculatorProviderBuilder != null)
			{
				calculatorProviderBuilder.setProvider(provider);
			}

			return this;
		}

		public virtual JcePBESecretKeyDecryptorBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			if (calculatorProviderBuilder != null)
			{
				calculatorProviderBuilder.setProvider(providerName);
			}

			return this;
		}

		public virtual PBESecretKeyDecryptor build(char[] passPhrase)
		{
			if (calculatorProvider == null)
			{
				calculatorProvider = calculatorProviderBuilder.build();
			}

			return new PBESecretKeyDecryptorAnonymousInnerClass(this, passPhrase, calculatorProvider);
		}

		public class PBESecretKeyDecryptorAnonymousInnerClass : PBESecretKeyDecryptor
		{
			private readonly JcePBESecretKeyDecryptorBuilder outerInstance;

			public PBESecretKeyDecryptorAnonymousInnerClass(JcePBESecretKeyDecryptorBuilder outerInstance, char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider) : base(passPhrase, calculatorProvider)
			{
				this.outerInstance = outerInstance;
			}

			public override byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
			{
				try
				{
					Cipher c = outerInstance.helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/CFB/NoPadding");

					c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new IvParameterSpec(iv));

					return c.doFinal(keyData, keyOff, keyLen);
				}
				catch (IllegalBlockSizeException e)
				{
					throw new PGPException("illegal block size: " + e.Message, e);
				}
				catch (BadPaddingException e)
				{
					throw new PGPException("bad padding: " + e.Message, e);
				}
				catch (InvalidAlgorithmParameterException e)
				{
					throw new PGPException("invalid parameter: " + e.Message, e);
				}
				catch (InvalidKeyException e)
				{
					throw new PGPException("invalid key: " + e.Message, e);
				}
			}
		}
	}

}