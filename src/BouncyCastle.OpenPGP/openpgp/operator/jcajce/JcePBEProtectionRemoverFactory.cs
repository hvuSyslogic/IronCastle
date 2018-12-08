namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePBEProtectionRemoverFactory : PBEProtectionRemoverFactory
	{
		private readonly char[] passPhrase;

		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private PGPDigestCalculatorProvider calculatorProvider;

		private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;

		public JcePBEProtectionRemoverFactory(char[] passPhrase)
		{
			this.passPhrase = passPhrase;
			this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
		}

		public JcePBEProtectionRemoverFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
		{
			this.passPhrase = passPhrase;
			this.calculatorProvider = calculatorProvider;
		}

		public virtual JcePBEProtectionRemoverFactory setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			if (calculatorProviderBuilder != null)
			{
				calculatorProviderBuilder.setProvider(provider);
			}

			return this;
		}

		public virtual JcePBEProtectionRemoverFactory setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			if (calculatorProviderBuilder != null)
			{
				calculatorProviderBuilder.setProvider(providerName);
			}

			return this;
		}

		public virtual PBESecretKeyDecryptor createDecryptor(string protection)
		{
			if (calculatorProvider == null)
			{
				calculatorProvider = calculatorProviderBuilder.build();
			}

			return new PBESecretKeyDecryptorAnonymousInnerClass(this, passPhrase, calculatorProvider);
		}

		public class PBESecretKeyDecryptorAnonymousInnerClass : PBESecretKeyDecryptor
		{
			private readonly JcePBEProtectionRemoverFactory outerInstance;

			public PBESecretKeyDecryptorAnonymousInnerClass(JcePBEProtectionRemoverFactory outerInstance, char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider) : base(passPhrase, calculatorProvider)
			{
				this.outerInstance = outerInstance;
			}

			public override byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
			{
				try
				{
					Cipher c = outerInstance.helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/CBC/NoPadding");

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