namespace org.bouncycastle.crypto.tls
{
	public abstract class ServerOnlyTlsAuthentication : TlsAuthentication
	{
		public abstract void notifyServerCertificate(Certificate serverCertificate);
		public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
		{
			return null;
		}
	}

}