namespace javax.crypto.interfaces
{

	/// <summary>
	/// The interface to a Diffie-Hellman public key.
	/// </summary>
	/// <seealso cref= DHKey </seealso>
	/// <seealso cref= DHPrivateKey </seealso>
	public abstract interface DHPublicKey : DHKey, PublicKey
	{
		/// <summary>
		/// Returns the public value, <code>y</code>.
		/// </summary>
		/// <returns> the public value, <code>y</code> </returns>
		BigInteger getY();
	}

}