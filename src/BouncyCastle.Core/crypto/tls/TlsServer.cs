using System.IO;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// Interface describing a TLS server endpoint.
	/// </summary>
	public interface TlsServer : TlsPeer
	{
		void init(TlsServerContext context);

		void notifyClientVersion(ProtocolVersion clientVersion);

		void notifyFallback(bool isFallback);

		void notifyOfferedCipherSuites(int[] offeredCipherSuites);

		void notifyOfferedCompressionMethods(short[] offeredCompressionMethods);

		// Hashtable is (Integer -> byte[])
		void processClientExtensions(Hashtable clientExtensions);

		ProtocolVersion getServerVersion();

		int getSelectedCipherSuite();

		short getSelectedCompressionMethod();

		// Hashtable is (Integer -> byte[])
		Hashtable getServerExtensions();

		// Vector is (SupplementalDataEntry)
		Vector getServerSupplementalData();

		TlsCredentials getCredentials();

		/// <summary>
		/// This method will be called (only) if the server included an extension of type
		/// "status_request" with empty "extension_data" in the extended server hello. See <i>RFC 3546
		/// 3.6. Certificate Status Request</i>. If a non-null <seealso cref="CertificateStatus"/> is returned, it
		/// is sent to the client as a handshake message of type "certificate_status".
		/// </summary>
		/// <returns> A <seealso cref="CertificateStatus"/> to be sent to the client (or null for none). </returns>
		/// <exception cref="IOException"> </exception>
		CertificateStatus getCertificateStatus();

		TlsKeyExchange getKeyExchange();

		CertificateRequest getCertificateRequest();

		// Vector is (SupplementalDataEntry)
		void processClientSupplementalData(Vector clientSupplementalData);

		/// <summary>
		/// Called by the protocol handler to report the client certificate, only if
		/// <seealso cref="#getCertificateRequest()"/> returned non-null.
		/// 
		/// Note: this method is responsible for certificate verification and validation.
		/// </summary>
		/// <param name="clientCertificate">
		///            the effective client certificate (may be an empty chain). </param>
		/// <exception cref="IOException"> </exception>
		void notifyClientCertificate(Certificate clientCertificate);

		/// <summary>
		/// RFC 5077 3.3. NewSessionTicket Handshake Message.
		/// <para>
		/// This method will be called (only) if a NewSessionTicket extension was sent by the server. See
		/// <i>RFC 5077 4. Recommended Ticket Construction</i> for recommended format and protection.
		/// 
		/// </para>
		/// </summary>
		/// <returns> The ticket. </returns>
		/// <exception cref="IOException"> </exception>
		NewSessionTicket getNewSessionTicket();
	}

}