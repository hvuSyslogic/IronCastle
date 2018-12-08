namespace org.bouncycastle.crypto.tls.test
{


	public class TlsTestConfig
	{
		public const bool DEBUG = false;

		/// <summary>
		/// Client does not authenticate, ignores any certificate request
		/// </summary>
		public const int CLIENT_AUTH_NONE = 0;

		/// <summary>
		/// Client will authenticate if it receives a certificate request
		/// </summary>
		public const int CLIENT_AUTH_VALID = 1;

		/// <summary>
		/// Client will authenticate if it receives a certificate request, with an invalid certificate
		/// </summary>
		public const int CLIENT_AUTH_INVALID_CERT = 2;

		/// <summary>
		/// Client will authenticate if it receives a certificate request, with an invalid CertificateVerify signature
		/// </summary>
		public const int CLIENT_AUTH_INVALID_VERIFY = 3;

		/// <summary>
		/// Server will not request a client certificate
		/// </summary>
		public const int SERVER_CERT_REQ_NONE = 0;

		/// <summary>
		/// Server will request a client certificate but receiving one is optional
		/// </summary>
		public const int SERVER_CERT_REQ_OPTIONAL = 1;

		/// <summary>
		/// Server will request a client certificate and receiving one is mandatory
		/// </summary>
		public const int SERVER_CERT_REQ_MANDATORY = 2;

		/// <summary>
		/// Configures the client authentication behaviour of the test client. Use CLIENT_AUTH_* constants.
		/// </summary>
		public int clientAuth = CLIENT_AUTH_VALID;

		/// <summary>
		/// If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
		/// be used for the CertificateVerify signature (if one is sent).
		/// </summary>
		public SignatureAndHashAlgorithm clientAuthSigAlg = null;

		/// <summary>
		/// If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
		/// be _claimed_ in the CertificateVerify (if one is sent), independently of what was actually used.
		/// </summary>
		public SignatureAndHashAlgorithm clientAuthSigAlgClaimed = null;

		/// <summary>
		/// Configures the minimum protocol version the client will accept. If null, uses the library's default.
		/// </summary>
		public ProtocolVersion clientMinimumVersion = null;

		/// <summary>
		/// Configures the protocol version the client will offer. If null, uses the library's default.
		/// </summary>
		public ProtocolVersion clientOfferVersion = null;

		/// <summary>
		/// Configures whether the client will indicate version fallback via TLS_FALLBACK_SCSV.
		/// </summary>
		public bool clientFallback = false;

		/// <summary>
		/// Configures whether a (TLS 1.2+) client will send the signature_algorithms extension in ClientHello.
		/// </summary>
		public bool clientSendSignatureAlgorithms = true;

		/// <summary>
		/// If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
		/// be used for the ServerKeyExchange signature (if one is sent).
		/// </summary>
		public SignatureAndHashAlgorithm serverAuthSigAlg = null;

		/// <summary>
		/// Configures whether the test server will send a certificate request.
		/// </summary>
		public int serverCertReq = SERVER_CERT_REQ_OPTIONAL;

		/// <summary>
		/// If TLS 1.2 or higher is negotiated, configures the set of supported signature algorithms in the
		/// CertificateRequest (if one is sent). If null, uses a default set.
		/// </summary>
		public Vector serverCertReqSigAlgs = null;

		/// <summary>
		/// Configures the maximum protocol version the server will accept. If null, uses the library's default.
		/// </summary>
		public ProtocolVersion serverMaximumVersion = null;

		/// <summary>
		/// Configures the minimum protocol version the server will accept. If null, uses the library's default.
		/// </summary>
		public ProtocolVersion serverMinimumVersion = null;

		/// <summary>
		/// Configures the connection end that a fatal alert is expected to be raised. Use ConnectionEnd.* constants.
		/// </summary>
		public int expectFatalAlertConnectionEnd = -1;

		/// <summary>
		/// Configures the type of fatal alert expected to be raised. Use AlertDescription.* constants.
		/// </summary>
		public short expectFatalAlertDescription = -1;

		public virtual void expectClientFatalAlert(short alertDescription)
		{
			this.expectFatalAlertConnectionEnd = ConnectionEnd.client;
			this.expectFatalAlertDescription = alertDescription;
		}

		public virtual void expectServerFatalAlert(short alertDescription)
		{
			this.expectFatalAlertConnectionEnd = ConnectionEnd.server;
			this.expectFatalAlertDescription = alertDescription;
		}
	}

}