namespace org.bouncycastle.openpgp.@operator.bc
{

	using S2K = org.bouncycastle.bcpg.S2K;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;

	/// <summary>
	/// A BC lightweight method generator for supporting PBE based encryption operations.
	/// </summary>
	public class BcPBEKeyEncryptionMethodGenerator : PBEKeyEncryptionMethodGenerator
	{
		/// <summary>
		/// Create a PBE encryption method generator using the provided digest and the default S2K count
		/// for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kDigestCalculator"> the digest calculator to use for key calculation. </param>
		public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator) : base(passPhrase, s2kDigestCalculator)
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the default SHA-1 digest and the default S2K
		/// count for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase) : this(passPhrase, new SHA1PGPDigestCalculator())
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the provided calculator and S2K count for key
		/// generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kDigestCalculator"> the digest calculator to use for key calculation. </param>
		/// <param name="s2kCount"> the single byte <seealso cref="S2K"/> count to use. </param>
		public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount) : base(passPhrase, s2kDigestCalculator, s2kCount)
		{
		}

		/// <summary>
		/// Create a PBE encryption method generator using the default SHA-1 digest calculator and a S2K
		/// count other than the default for key generation.
		/// </summary>
		/// <param name="passPhrase"> the passphrase to use as the primary source of key material. </param>
		/// <param name="s2kCount"> the single byte <seealso cref="S2K"/> count to use. </param>
		public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount) : base(passPhrase, new SHA1PGPDigestCalculator(), s2kCount)
		{
		}

		public override PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
		{
			base.setSecureRandom(random);

			return this;
		}

		public override byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
		{
			try
			{
				BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);
				BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(true, engine, key, new byte[engine.getBlockSize()]);

				byte[] @out = new byte[sessionInfo.Length];

				int len = cipher.processBytes(sessionInfo, 0, sessionInfo.Length, @out, 0);

				len += cipher.doFinal(@out, len);

				return @out;
			}
			catch (InvalidCipherTextException e)
			{
				throw new PGPException("encryption failed: " + e.Message, e);
			}
		}
	}

}