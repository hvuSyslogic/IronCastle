using System.IO;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// Interface describing a TLS client endpoint.
	/// </summary>
	public interface TlsClient : TlsPeer
	{
		void init(TlsClientContext context);

		/// <summary>
		/// Return the session this client wants to resume, if any. Note that the peer's certificate
		/// chain for the session (if any) may need to be periodically revalidated.
		/// </summary>
		/// <returns> A <seealso cref="TlsSession"/> representing the resumable session to be used for this
		///         connection, or null to use a new session. </returns>
		/// <seealso cref= SessionParameters#getPeerCertificate() </seealso>
		TlsSession getSessionToResume();

		/// <summary>
		/// Return the <seealso cref="ProtocolVersion"/> to use for the <code>TLSPlaintext.version</code> field prior to
		/// receiving the server version. NOTE: This method is <b>not</b> called for DTLS.
		/// 
		/// <para>
		/// See RFC 5246 E.1.: "TLS clients that wish to negotiate with older servers MAY send any value
		/// {03,XX} as the record layer version number. Typical values would be {03,00}, the lowest
		/// version number supported by the client, and the value of ClientHello.client_version. No
		/// single value will guarantee interoperability with all old servers, but this is a complex
		/// topic beyond the scope of this document."
		/// </para>
		/// </summary>
		/// <returns> The <seealso cref="ProtocolVersion"/> to use. </returns>
		ProtocolVersion getClientHelloRecordLayerVersion();

		ProtocolVersion getClientVersion();

		bool isFallback();

		int[] getCipherSuites();

		short[] getCompressionMethods();

		// Hashtable is (Integer -> byte[])
		Hashtable getClientExtensions();

		void notifyServerVersion(ProtocolVersion selectedVersion);

		/// <summary>
		/// Notifies the client of the session_id sent in the ServerHello.
		/// </summary>
		/// <param name="sessionID"> </param>
		/// <seealso cref= TlsContext#getResumableSession() </seealso>
		void notifySessionID(byte[] sessionID);

		void notifySelectedCipherSuite(int selectedCipherSuite);

		void notifySelectedCompressionMethod(short selectedCompressionMethod);

		// Hashtable is (Integer -> byte[])
		void processServerExtensions(Hashtable serverExtensions);

		// Vector is (SupplementalDataEntry)
		void processServerSupplementalData(Vector serverSupplementalData);

		TlsKeyExchange getKeyExchange();

		TlsAuthentication getAuthentication();

		// Vector is (SupplementalDataEntry)
		Vector getClientSupplementalData();

		/// <summary>
		/// RFC 5077 3.3. NewSessionTicket Handshake Message
		/// <para>
		/// This method will be called (only) when a NewSessionTicket handshake message is received. The
		/// ticket is opaque to the client and clients MUST NOT examine the ticket under the assumption
		/// that it complies with e.g. <i>RFC 5077 4. Recommended Ticket Construction</i>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="newSessionTicket"> The ticket. </param>
		/// <exception cref="IOException"> </exception>
		void notifyNewSessionTicket(NewSessionTicket newSessionTicket);
	}

}