namespace org.bouncycastle.openpgp.@operator
{

	using S2K = org.bouncycastle.bcpg.S2K;

	public abstract class PBESecretKeyEncryptor
	{
		protected internal int encAlgorithm;
		protected internal char[] passPhrase;
		protected internal PGPDigestCalculator s2kDigestCalculator;
		protected internal int s2kCount;
		protected internal S2K s2k;

		protected internal SecureRandom random;

		public PBESecretKeyEncryptor(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, SecureRandom random, char[] passPhrase) : this(encAlgorithm, s2kDigestCalculator, 0x60, random, passPhrase)
		{
		}

		public PBESecretKeyEncryptor(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount, SecureRandom random, char[] passPhrase)
		{
			this.encAlgorithm = encAlgorithm;
			this.passPhrase = passPhrase;
			this.random = random;
			this.s2kDigestCalculator = s2kDigestCalculator;

			if (s2kCount < 0 || s2kCount > 0xff)
			{
				throw new IllegalArgumentException("s2kCount value outside of range 0 to 255.");
			}

			this.s2kCount = s2kCount;
		}

		public virtual int getAlgorithm()
		{
			return encAlgorithm;
		}

		public virtual int getHashAlgorithm()
		{
			if (s2kDigestCalculator != null)
			{
				return s2kDigestCalculator.getAlgorithm();
			}

			return -1;
		}

		public virtual byte[] getKey()
		{
			return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
		}

		public virtual S2K getS2K()
		{
			return s2k;
		}

		/// <summary>
		/// Key encryption method invoked for V4 keys and greater.
		/// </summary>
		/// <param name="keyData"> raw key data </param>
		/// <param name="keyOff"> offset into raw key data </param>
		/// <param name="keyLen"> length of key data to use. </param>
		/// <returns> an encryption of the passed in keyData. </returns>
		/// <exception cref="PGPException"> on error in the underlying encryption process. </exception>
		public virtual byte[] encryptKeyData(byte[] keyData, int keyOff, int keyLen)
		{
			if (s2k == null)
			{
				byte[] iv = new byte[8];

				random.nextBytes(iv);

				s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, s2kCount);
			}

			return encryptKeyData(getKey(), keyData, keyOff, keyLen);
		}

		public abstract byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen);

		/// <summary>
		/// Encrypt the passed in keyData using the key and the iv provided.
		/// <para>
		/// This method is only used for processing version 3 keys.
		/// </para>
		/// </summary>
		public virtual byte[] encryptKeyData(byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
		{
			throw new PGPException("encryption of version 3 keys not supported.");
		}

		public abstract byte[] getCipherIV();
	}

}