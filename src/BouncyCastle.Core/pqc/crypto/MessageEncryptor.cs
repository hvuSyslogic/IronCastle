namespace org.bouncycastle.pqc.crypto
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;

	/// <summary>
	/// Base interface for a PQC encryption algorithm.
	/// </summary>
	public interface MessageEncryptor
	{

		/// 
		/// <param name="forEncrypting"> true if we are encrypting a signature, false
		/// otherwise. </param>
		/// <param name="param"> key parameters for encryption or decryption. </param>
		void init(bool forEncrypting, CipherParameters param);

		/// 
		/// <param name="message"> the message to be signed. </param>
		byte[] messageEncrypt(byte[] message);

		/// 
		/// <param name="cipher"> the cipher text of the message </param>
		/// <exception cref="InvalidCipherTextException"> </exception>
		byte[] messageDecrypt(byte[] cipher);
	}

}