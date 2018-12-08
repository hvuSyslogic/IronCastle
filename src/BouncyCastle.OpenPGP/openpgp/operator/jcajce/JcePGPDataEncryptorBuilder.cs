namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	/// <summary>
	/// <seealso cref="PGPDataEncryptorBuilder"/> implementation that sources cryptographic primitives using the
	/// JCE APIs.
	/// <para>
	/// By default, cryptographic primitives will be loaded using the default JCE load order (i.e.
	/// without specifying a provider). 
	/// A specific provider can be specified using one of the <seealso cref="#setProvider(String)"/> methods.
	/// </para>
	/// </summary>
	public class JcePGPDataEncryptorBuilder : PGPDataEncryptorBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private SecureRandom random;
		private bool withIntegrityPacket;
		private int encAlgorithm;

		/// <summary>
		/// Constructs a new data encryptor builder for a specified cipher type.
		/// </summary>
		/// <param name="encAlgorithm"> one of the {@link SymmetricKeyAlgorithmTags supported symmetric cipher
		///            algorithms}. May not be <seealso cref="SymmetricKeyAlgorithmTags#NULL"/>. </param>
		public JcePGPDataEncryptorBuilder(int encAlgorithm)
		{
			this.encAlgorithm = encAlgorithm;

			if (encAlgorithm == 0)
			{
				throw new IllegalArgumentException("null cipher specified");
			}
		}

		/// <summary>
		/// Sets whether or not the resulting encrypted data will be protected using an integrity packet.
		/// </summary>
		/// <param name="withIntegrityPacket"> true if an integrity packet is to be included, false otherwise. </param>
		/// <returns> the current builder. </returns>
		public virtual JcePGPDataEncryptorBuilder setWithIntegrityPacket(bool withIntegrityPacket)
		{
			this.withIntegrityPacket = withIntegrityPacket;

			return this;
		}

		/// <summary>
		/// Sets the JCE provider to source cryptographic primitives from.
		/// </summary>
		/// <param name="provider"> the JCE provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcePGPDataEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		/// <summary>
		/// Sets the JCE provider to source cryptographic primitives from.
		/// </summary>
		/// <param name="providerName"> the name of the JCE provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcePGPDataEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		/// <summary>
		/// Provide a user defined source of randomness.
		/// <para>
		/// If no SecureRandom is configured, a default SecureRandom will be used.
		/// </para> </summary>
		/// <param name="random"> the secure random to be used. </param>
		/// <returns> the current builder. </returns>
		public virtual JcePGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual int getAlgorithm()
		{
			return encAlgorithm;
		}

		public virtual SecureRandom getSecureRandom()
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			return random;
		}

		public virtual PGPDataEncryptor build(byte[] keyBytes)
		{
			return new MyPGPDataEncryptor(this, keyBytes);
		}

		public class MyPGPDataEncryptor : PGPDataEncryptor
		{
			private readonly JcePGPDataEncryptorBuilder outerInstance;

			internal readonly Cipher c;

			public MyPGPDataEncryptor(JcePGPDataEncryptorBuilder outerInstance, byte[] keyBytes)
			{
				this.outerInstance = outerInstance;
				c = outerInstance.helper.createStreamCipher(outerInstance.encAlgorithm, outerInstance.withIntegrityPacket);

				try
				{
					if (outerInstance.withIntegrityPacket)
					{
						byte[] iv = new byte[c.getBlockSize()];

						c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(outerInstance.encAlgorithm, keyBytes), new IvParameterSpec(iv));
					}
					else
					{
						c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(outerInstance.encAlgorithm, keyBytes));
					}
				}
				catch (InvalidKeyException e)
				{
					throw new PGPException("invalid key: " + e.Message, e);
				}
				catch (InvalidAlgorithmParameterException e)
				{
					throw new PGPException("imvalid algorithm parameter: " + e.Message, e);
				}
			}

			public virtual OutputStream getOutputStream(OutputStream @out)
			{
				return new CipherOutputStream(@out, c);
			}

			public virtual PGPDigestCalculator getIntegrityCalculator()
			{
				if (outerInstance.withIntegrityPacket)
				{
					return new SHA1PGPDigestCalculator();
				}

				return null;
			}

			public virtual int getBlockSize()
			{
				return c.getBlockSize();
			}
		}
	}

}