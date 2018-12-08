namespace org.bouncycastle.crypto.tls
{
	public abstract class AbstractTlsEncryptionCredentials : AbstractTlsCredentials, TlsEncryptionCredentials
	{
		public abstract byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret);
		public override abstract Certificate getCertificate();
	}

}