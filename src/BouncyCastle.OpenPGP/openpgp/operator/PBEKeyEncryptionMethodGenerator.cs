namespace org.bouncycastle.openpgp.@operator
{

	using ContainedPacket = org.bouncycastle.bcpg.ContainedPacket;
	using S2K = org.bouncycastle.bcpg.S2K;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using SymmetricKeyEncSessionPacket = org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;

	/// <summary>
	/// PGP style PBE encryption method.
	/// <para>
	/// A pass phrase is used to generate an encryption key using the PGP <seealso cref="S2K string-to-key"/>
	/// method. This class always uses the {@link S2K#SALTED_AND_ITERATED salted and iterated form of the
	/// S2K algorithm}.
	/// </para>
	/// </para><para>
	/// Note that the iteration count provided to this method is a single byte as described by the
	/// <seealso cref="S2K"/> algorithm, and the actual iteration count ranges exponentially from
	/// <code>0x01</code> == 1088 to <code>0xFF</code> == 65,011,712.
	/// </p>
	/// </summary>
	public abstract class PBEKeyEncryptionMethodGenerator : PGPKeyEncryptionMethodGenerator
	{
		private char[] passPhrase;
		private PGPDigestCalculator s2kDigestCalculator;
		private S2K s2k;
		private SecureRandom random;
		private int s2kCount;

		/// <summary>
		/// Construct a PBE key generator using the default iteration count (<code>0x60</code> == 65536
		/// iterations).
		/// </summary>
		/// <param name="passPhrase"> the pass phrase to encrypt with. </param>
		/// <param name="s2kDigestCalculator"> a digest calculator to use in the string-to-key function. </param>
		public PBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator) : this(passPhrase, s2kDigestCalculator, 0x60)
		{
		}

		/// <summary>
		/// Construct a PBE key generator using a specific iteration level.
		/// </summary>
		/// <param name="passPhrase"> the pass phrase to encrypt with. </param>
		/// <param name="s2kDigestCalculator"> a digest calculator to use in the string-to-key function. </param>
		/// <param name="s2kCount"> a single byte <seealso cref="S2K"/> iteration count specifier, which is translated to
		///            an actual iteration count by the S2K class. </param>
		public PBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
		{
			this.passPhrase = passPhrase;
			this.s2kDigestCalculator = s2kDigestCalculator;

			if (s2kCount < 0 || s2kCount > 0xff)
			{
				throw new IllegalArgumentException("s2kCount value outside of range 0 to 255.");
			}

			this.s2kCount = s2kCount;
		}

		/// <summary>
		/// Sets a user defined source of randomness.
		/// <para>
		/// If no SecureRandom is configured, a default SecureRandom will be used.
		/// </para> </summary>
		/// <returns> the current generator. </returns>
		public virtual PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Generate a key for a symmetric encryption algorithm using the PBE configuration in this
		/// method.
		/// </summary>
		/// <param name="encAlgorithm"> the <seealso cref="SymmetricKeyAlgorithmTags encryption algorithm"/> to generate
		///            the key for. </param>
		/// <returns> the bytes of the generated key. </returns>
		/// <exception cref="PGPException"> if an error occurs performing the string-to-key generation. </exception>
		public virtual byte[] getKey(int encAlgorithm)
		{
			if (s2k == null)
			{
				byte[] iv = new byte[8];

				if (random == null)
				{
					random = new SecureRandom();
				}

				random.nextBytes(iv);

				s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, s2kCount);
			}

			return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
		}

		public override ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
		{
			byte[] key = getKey(encAlgorithm);

			if (sessionInfo == null)
			{
				return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, null);
			}

			//
			// the passed in session info has the an RSA/ElGamal checksum added to it, for PBE this is not included.
			//
			byte[] nSessionInfo = new byte[sessionInfo.Length - 2];

			JavaSystem.arraycopy(sessionInfo, 0, nSessionInfo, 0, nSessionInfo.Length);

			return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, encryptSessionInfo(encAlgorithm, key, nSessionInfo));
		}

		public abstract byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo);
	}

}