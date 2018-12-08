namespace org.bouncycastle.crypto
{
	/// <summary>
	/// The basic interface for key encapsulation mechanisms.
	/// </summary>
	public interface KeyEncapsulation
	{
		/// <summary>
		/// Initialise the key encapsulation mechanism.
		/// </summary>
		void init(CipherParameters param);

		/// <summary>
		/// Encapsulate a randomly generated session key.    
		/// </summary>
		CipherParameters encrypt(byte[] @out, int outOff, int keyLen);

		/// <summary>
		/// Decapsulate an encapsulated session key.
		/// </summary>
		CipherParameters decrypt(byte[] @in, int inOff, int inLen, int keyLen);
	}

}