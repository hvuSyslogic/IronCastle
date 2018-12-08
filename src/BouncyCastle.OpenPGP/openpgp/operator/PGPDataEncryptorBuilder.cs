namespace org.bouncycastle.openpgp.@operator
{

	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

	/// <summary>
	/// A builder for <seealso cref="PGPDataEncryptor"/> instances, which can be used to encrypt data objects.
	/// </summary>
	public interface PGPDataEncryptorBuilder
	{
		/// <summary>
		/// The encryption algorithm used by data encryptors created by this builder.
		/// </summary>
		/// <returns> one of the <seealso cref="SymmetricKeyAlgorithmTags symmetric encryption algorithms"/>. </returns>
		int getAlgorithm();

		/// <summary>
		/// Builds a data encryptor using the algorithm configured for this builder.
		/// </summary>
		/// <param name="keyBytes"> the bytes of the key to use for the cipher. </param>
		/// <returns> a data encryptor with an initialised cipher. </returns>
		/// <exception cref="PGPException"> if an error occurs initialising the configured encryption. </exception>
		PGPDataEncryptor build(byte[] keyBytes);

		/// <summary>
		/// Gets the SecureRandom instance used by this builder.
		/// <para>
		/// If a SecureRandom has not been explicitly configured, a default <seealso cref="SecureRandom"/> is
		/// constructed and retained by the this builder.</para>
		/// </summary>
		SecureRandom getSecureRandom();
	}

}