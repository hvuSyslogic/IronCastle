using System.IO;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// Base interface to provide TLS authentication credentials.
	/// </summary>
	public interface TlsAuthentication
	{
		/// <summary>
		/// Called by the protocol handler to report the server certificate
		/// Note: this method is responsible for certificate verification and validation
		/// </summary>
		/// <param name="serverCertificate"> the server certificate received </param>
		/// <exception cref="IOException"> </exception>
		void notifyServerCertificate(Certificate serverCertificate);

		/// <summary>
		/// Return client credentials in response to server's certificate request
		/// </summary>
		/// <param name="certificateRequest"> details of the certificate request </param>
		/// <returns> a TlsCredentials object or null for no client authentication </returns>
		/// <exception cref="IOException"> </exception>
		TlsCredentials getClientCredentials(CertificateRequest certificateRequest);
	}

}