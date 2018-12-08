using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// A generic interface for key exchange implementations in (D)TLS.
	/// </summary>
	public interface TlsKeyExchange
	{
		void init(TlsContext context);

		void skipServerCredentials();

		void processServerCredentials(TlsCredentials serverCredentials);

		void processServerCertificate(Certificate serverCertificate);

		bool requiresServerKeyExchange();

		byte[] generateServerKeyExchange();

		void skipServerKeyExchange();

		void processServerKeyExchange(InputStream input);

		void validateCertificateRequest(CertificateRequest certificateRequest);

		void skipClientCredentials();

		void processClientCredentials(TlsCredentials clientCredentials);

		void processClientCertificate(Certificate clientCertificate);

		void generateClientKeyExchange(OutputStream output);

		void processClientKeyExchange(InputStream input);

		byte[] generatePremasterSecret();
	}

}