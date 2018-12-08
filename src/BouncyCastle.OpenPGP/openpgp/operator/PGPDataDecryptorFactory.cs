namespace org.bouncycastle.openpgp.@operator
{
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

	/// <summary>
	/// Base interface of factories for <seealso cref="PGPDataDecryptor"/>.
	/// </summary>
	public interface PGPDataDecryptorFactory
	{
		/// <summary>
		/// Constructs a data decryptor.
		/// </summary>
		/// <param name="withIntegrityPacket"> <code>true</code> if the packet to be decrypted has integrity
		///            checking enabled. </param>
		/// <param name="encAlgorithm"> the identifier of the {@link SymmetricKeyAlgorithmTags encryption
		///            algorithm} to decrypt with. </param>
		/// <param name="key"> the bytes of the key for the cipher. </param>
		/// <returns> a data decryptor that can decrypt (and verify) streams of encrypted data. </returns>
		/// <exception cref="PGPException"> if an error occurs initialising the decryption and integrity checking
		///             functions. </exception>
		PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key);
	}

}