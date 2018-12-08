namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcePBESecretKeyEncryptorBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private int encAlgorithm;
		private PGPDigestCalculator s2kDigestCalculator;
		private SecureRandom random;
		private int s2kCount = 0x60;

		public JcePBESecretKeyEncryptorBuilder(int encAlgorithm) : this(encAlgorithm, new SHA1PGPDigestCalculator())
		{
		}

		/// <summary>
		/// Create a SecretKeyEncryptorBuilder with the S2K count different to the default of 0x60.
		/// </summary>
		/// <param name="encAlgorithm"> encryption algorithm to use. </param>
		/// <param name="s2kCount"> iteration count to use for S2K function. </param>
		public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, int s2kCount) : this(encAlgorithm, new SHA1PGPDigestCalculator(), s2kCount)
		{
		}

		/// <summary>
		/// Create a builder which will make encryptors using the passed in digest calculator. If a MD5 calculator is
		/// passed in the builder will assume the encryptors are for use with version 3 keys.
		/// </summary>
		/// <param name="encAlgorithm">  encryption algorithm to use. </param>
		/// <param name="s2kDigestCalculator"> digest calculator to use. </param>
		public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator) : this(encAlgorithm, s2kDigestCalculator, 0x60)
		{
		}

		/// <summary>
		/// Create an SecretKeyEncryptorBuilder with the S2k count different to the default of 0x60, and the S2K digest
		/// different from SHA-1.
		/// </summary>
		/// <param name="encAlgorithm"> encryption algorithm to use. </param>
		/// <param name="s2kDigestCalculator"> digest calculator to use. </param>
		/// <param name="s2kCount"> iteration count to use for S2K function. </param>
		public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
		{
			this.encAlgorithm = encAlgorithm;
			this.s2kDigestCalculator = s2kDigestCalculator;

			if (s2kCount < 0 || s2kCount > 0xff)
			{
				throw new IllegalArgumentException("s2KCount value outside of range 0 to 255.");
			}

			this.s2kCount = s2kCount;
		}

		public virtual JcePBESecretKeyEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcePBESecretKeyEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

	   /// <summary>
	   /// Provide a user defined source of randomness.
	   /// </summary>
	   /// <param name="random">  the secure random to be used. </param>
	   /// <returns>  the current builder. </returns>
		public virtual JcePBESecretKeyEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual PBESecretKeyEncryptor build(char[] passPhrase)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			return new PBESecretKeyEncryptorAnonymousInnerClass(this, encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase);
		}

		public class PBESecretKeyEncryptorAnonymousInnerClass : PBESecretKeyEncryptor
		{
			private readonly JcePBESecretKeyEncryptorBuilder outerInstance;

			public PBESecretKeyEncryptorAnonymousInnerClass(JcePBESecretKeyEncryptorBuilder outerInstance, int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount, SecureRandom random, char[] passPhrase) : base(encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase)
			{
				this.outerInstance = outerInstance;
			}

			private Cipher c;
			private byte[] iv;

			public override byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
			{
				try
				{
					c = outerInstance.helper.createCipher(PGPUtil.getSymmetricCipherName(this.encAlgorithm) + "/CFB/NoPadding");

					c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(this.encAlgorithm, key), this.random);

					iv = c.getIV();

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
				catch (InvalidKeyException e)
				{
					throw new PGPException("invalid key: " + e.Message, e);
				}
			}

			public override byte[] encryptKeyData(byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
			{
				try
				{
					c = outerInstance.helper.createCipher(PGPUtil.getSymmetricCipherName(this.encAlgorithm) + "/CFB/NoPadding");

					c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(this.encAlgorithm, key), new IvParameterSpec(iv));

					this.iv = iv;

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
				catch (InvalidKeyException e)
				{
					throw new PGPException("invalid key: " + e.Message, e);
				}
				catch (InvalidAlgorithmParameterException e)
				{
					throw new PGPException("invalid iv: " + e.Message, e);
				}
			}

			public override byte[] getCipherIV()
			{
				return iv;
			}
		}
	}

}