namespace org.bouncycastle.crypto.tls
{

	public interface TlsCipherFactory
	{
		/// <summary>
		/// See enumeration classes EncryptionAlgorithm, MACAlgorithm for appropriate argument values
		/// </summary>
		TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm);
	}

}