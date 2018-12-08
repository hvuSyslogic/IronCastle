namespace org.bouncycastle.openpgp.@operator
{

	/// <summary>
	/// A decryptor that wraps a stream of PGP encrypted data to decrypt, and optionally integrity check,
	/// the data.
	/// </summary>
	public interface PGPDataDecryptor
	{
		/// <summary>
		/// Wraps an encrypted data stream with a stream that will return the decrypted data.
		/// </summary>
		/// <param name="in"> the encrypted data. </param>
		/// <returns> a decrypting stream. </returns>
		InputStream getInputStream(InputStream @in);

		/// <summary>
		/// Obtains the block size of the encryption algorithm used in this decryptor.
		/// </summary>
		/// <returns> the block size of the cipher in bytes. </returns>
		int getBlockSize();

		/// <summary>
		/// Obtains the digest calculator used to verify the integrity check.
		/// </summary>
		PGPDigestCalculator getIntegrityCalculator();
	}

}