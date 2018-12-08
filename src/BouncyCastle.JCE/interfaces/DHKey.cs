namespace javax.crypto.interfaces
{

	/// <summary>
	/// The interface to a Diffie-Hellman key.
	/// </summary>
	/// <seealso cref= DHParameterSpec </seealso>
	/// <seealso cref= DHPublicKey </seealso>
	/// <seealso cref= DHPrivateKey </seealso>
	public abstract interface DHKey
	{
		/// <summary>
		/// Returns the key parameters.
		/// </summary>
		/// <returns> the key parameters </returns>
		DHParameterSpec getParams();
	}

}