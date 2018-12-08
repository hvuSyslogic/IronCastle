namespace org.bouncycastle.openpgp.@operator
{
	using S2K = org.bouncycastle.bcpg.S2K;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

	/// <summary>
	/// A factory for performing PBE decryption operations.
	/// </summary>
	public abstract class PBEDataDecryptorFactory : PGPDataDecryptorFactory
	{
		public abstract PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key);
		private char[] passPhrase;
		private PGPDigestCalculatorProvider calculatorProvider;

		/// <summary>
		/// Construct a PBE data decryptor factory.
		/// </summary>
		/// <param name="passPhrase"> the pass phrase to generate decryption keys with. </param>
		/// <param name="calculatorProvider"> the digest to use in key generation. </param>
		public PBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
		{
			this.passPhrase = passPhrase;
			this.calculatorProvider = calculatorProvider;
		}

		/// <summary>
		/// Generates an encryption key using the pass phrase and digest calculator configured for this
		/// factory.
		/// </summary>
		/// <param name="keyAlgorithm"> the <seealso cref="SymmetricKeyAlgorithmTags encryption algorithm"/> to generate a
		///            key for. </param>
		/// <param name="s2k"> the string-to-key specification to use to generate the key. </param>
		/// <returns> the key bytes for the encryption algorithm, generated using the pass phrase of this
		///         factory. </returns>
		/// <exception cref="PGPException"> if an error occurs generating the key. </exception>
		public virtual byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
		{
			return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, keyAlgorithm, s2k, passPhrase);
		}

		/// <summary>
		/// Decrypts session data from an encrypted data packet.
		/// </summary>
		/// <param name="keyAlgorithm"> the <seealso cref="SymmetricKeyAlgorithmTags encryption algorithm"/> used to
		///            encrypt the session data. </param>
		/// <param name="key"> the key bytes for the encryption algorithm. </param>
		/// <param name="seckKeyData"> the encrypted session data to decrypt. </param>
		/// <returns> the decrypted session data. </returns>
		/// <exception cref="PGPException"> if an error occurs decrypting the session data. </exception>
		public abstract byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] seckKeyData);
	}

}