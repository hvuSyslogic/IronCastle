using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{
	public abstract class AbstractTlsSignerCredentials : AbstractTlsCredentials, TlsSignerCredentials
	{
		public abstract byte[] generateCertificateSignature(byte[] hash);
		public override abstract Certificate getCertificate();
		public virtual SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
		{
			throw new IllegalStateException("TlsSignerCredentials implementation does not support (D)TLS 1.2+");
		}
	}

}