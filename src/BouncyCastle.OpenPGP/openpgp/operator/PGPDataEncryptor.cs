namespace org.bouncycastle.openpgp.@operator
{

	/// <summary>
	/// A data encryptor, combining a cipher instance and an optional integrity check calculator.
	/// <para>
	/// <seealso cref="PGPDataEncryptor"/> instances are generally not constructed directly, but obtained from a
	/// <seealso cref="PGPDataEncryptorBuilder"/>.
	/// </para>
	/// </summary>
	public interface PGPDataEncryptor
	{
		/// <summary>
		/// Constructs an encrypting output stream that encrypts data using the underlying cipher of this
		/// encryptor.
		/// <para>
		/// The cipher instance in this encryptor is used for all output streams obtained from this
		/// method, so it should only be invoked once.
		/// </para> </summary>
		/// <param name="out"> the stream to wrap and write encrypted data to. </param>
		/// <returns> a cipher output stream appropriate to the type of this data encryptor. </returns>
		OutputStream getOutputStream(OutputStream @out);

		/// <summary>
		/// Obtains the integrity check calculator configured for this encryptor instance.
		/// </summary>
		/// <returns> the integrity check calculator, or <code>null</code> if no integrity checking was
		///         configured. </returns>
		PGPDigestCalculator getIntegrityCalculator();

		/// <summary>
		/// Gets the block size of the underlying cipher used by this encryptor.
		/// </summary>
		/// <returns> the block size in bytes. </returns>
		int getBlockSize();
	}

}