namespace org.bouncycastle.crypto.tls
{

	public interface TlsSignerCredentials : TlsCredentials
	{
		byte[] generateCertificateSignature(byte[] hash);

		SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();
	}

}