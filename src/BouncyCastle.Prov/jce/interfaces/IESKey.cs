namespace org.bouncycastle.jce.interfaces
{

	/// <summary>
	/// key pair for use with an integrated encryptor
	/// </summary>
	public interface IESKey : Key
	{
		/// <summary>
		/// return the intended recipient's/sender's public key.
		/// </summary>
		PublicKey getPublic();

		/// <summary>
		/// return the local private key.
		/// </summary>
		PrivateKey getPrivate();
	}

}