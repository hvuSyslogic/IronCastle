namespace org.bouncycastle.crypto.tls
{

	public interface TlsEncryptionCredentials : TlsCredentials
	{
		byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret);
	}

}