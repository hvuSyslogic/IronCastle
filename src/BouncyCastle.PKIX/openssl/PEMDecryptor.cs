namespace org.bouncycastle.openssl
{
	/// <summary>
	/// Base interface for decryption operations.
	/// </summary>
	public interface PEMDecryptor
	{
		/// <summary>
		/// Decrypt the passed in data using the associated IV and the decryptor's key state.
		/// </summary>
		/// <param name="data"> the encrypted data </param>
		/// <param name="iv"> the initialisation vector associated with the decryption. </param>
		/// <returns> the decrypted data. </returns>
		/// <exception cref="PEMException"> in the event of an issue. </exception>
		byte[] decrypt(byte[] data, byte[] iv);
	}

}