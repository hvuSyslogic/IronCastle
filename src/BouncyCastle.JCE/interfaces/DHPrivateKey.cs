namespace javax.crypto.interfaces
{

	/// <summary>
	/// The interface to a Diffie-Hellman private key.
	/// </summary>
	/// <seealso cref= DHKey </seealso>
	/// <seealso cref= DHPublicKey </seealso>
	public abstract interface DHPrivateKey : DHKey, PrivateKey
	{
		/// <summary>
		/// Returns the private value, <code>x</code>.
		/// </summary>
		/// <returns> the private value, <code>x</code> </returns>
		BigInteger getX();
	}

}