namespace org.bouncycastle.openpgp.@operator.bc
{

	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherOutputStream = org.bouncycastle.crypto.io.CipherOutputStream;

	/// <summary>
	/// <seealso cref="PGPDataEncryptorBuilder"/> implementation that uses the Bouncy Castle lightweight API to
	/// implement cryptographic primitives.
	/// </summary>
	public class BcPGPDataEncryptorBuilder : PGPDataEncryptorBuilder
	{
		private SecureRandom random;
		private bool withIntegrityPacket;
		private int encAlgorithm;

		/// <summary>
		/// Constructs a new data encryptor builder for a specified cipher type.
		/// </summary>
		/// <param name="encAlgorithm"> one of the {@link SymmetricKeyAlgorithmTags supported symmetric cipher
		///            algorithms}. May not be <seealso cref="SymmetricKeyAlgorithmTags#NULL"/>. </param>
		public BcPGPDataEncryptorBuilder(int encAlgorithm)
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
		public virtual BcPGPDataEncryptorBuilder setWithIntegrityPacket(bool withIntegrityPacket)
		{
			this.withIntegrityPacket = withIntegrityPacket;

			return this;
		}

		/// <summary>
		/// Provide a user defined source of randomness.
		/// <para>
		/// If no SecureRandom is configured, a default SecureRandom will be used.
		/// </para> </summary>
		/// <param name="random"> the secure random to be used. </param>
		/// <returns> the current builder. </returns>
		public virtual BcPGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
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
			private readonly BcPGPDataEncryptorBuilder outerInstance;

			internal readonly BufferedBlockCipher c;

			public MyPGPDataEncryptor(BcPGPDataEncryptorBuilder outerInstance, byte[] keyBytes)
			{
				this.outerInstance = outerInstance;
				BlockCipher engine = BcImplProvider.createBlockCipher(outerInstance.encAlgorithm);

				try
				{
					c = BcUtil.createStreamCipher(true, engine, outerInstance.withIntegrityPacket, keyBytes);
				}
				catch (IllegalArgumentException e)
				{
					throw new PGPException("invalid parameters: " + e.getMessage(), e);
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