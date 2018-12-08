namespace org.bouncycastle.crypto.tls
{
	public abstract class AbstractTlsCredentials : TlsCredentials
	{
		public abstract Certificate getCertificate();
	}

}