namespace org.bouncycastle.jce.interfaces
{

	/// <summary>
	/// all BC provider keystores implement this interface.
	/// </summary>
	public interface BCKeyStore
	{
		/// <summary>
		/// set the random source for the key store
		/// </summary>
		void setRandom(SecureRandom random);
	}

}