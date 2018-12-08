using System;

namespace org.bouncycastle.crypto.tls
{

	public interface TlsPeer
	{
		/// <summary>
		/// This implementation supports RFC 7627 and will always negotiate the extended_master_secret
		/// extension where possible. When connecting to a peer that does not offer/accept this
		/// extension, it is recommended to abort the handshake. This option is provided for
		/// interoperability with legacy peers, although some TLS features will be disabled in that case
		/// (see RFC 7627 5.4).
		/// </summary>
		/// <returns> <code>true</code> if the handshake should be aborted when the peer does not negotiate
		///         the extended_master_secret extension, or <code>false</code> to support legacy
		///         interoperability. </returns>
		bool requiresExtendedMasterSecret();

		/// <summary>
		/// draft-mathewson-no-gmtunixtime-00 2. "If existing users of a TLS implementation may rely on
		/// gmt_unix_time containing the current time, we recommend that implementors MAY provide the
		/// ability to set gmt_unix_time as an option only, off by default."
		/// </summary>
		/// <returns> <code>true</code> if the current time should be used in the gmt_unix_time field of
		///         Random, or <code>false</code> if gmt_unix_time should contain a cryptographically
		///         random value. </returns>
		bool shouldUseGMTUnixTime();

		void notifySecureRenegotiation(bool secureNegotiation);

		TlsCompression getCompression();

		TlsCipher getCipher();

		/// <summary>
		/// This method will be called when an alert is raised by the protocol.
		/// </summary>
		/// <param name="alertLevel">       <seealso cref="AlertLevel"/> </param>
		/// <param name="alertDescription"> <seealso cref="AlertDescription"/> </param>
		/// <param name="message">          A human-readable message explaining what caused this alert. May be null. </param>
		/// <param name="cause">            The <seealso cref="Throwable"/> that caused this alert to be raised. May be null. </param>
		void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause);

		/// <summary>
		/// This method will be called when an alert is received from the remote peer.
		/// </summary>
		/// <param name="alertLevel">       <seealso cref="AlertLevel"/> </param>
		/// <param name="alertDescription"> <seealso cref="AlertDescription"/> </param>
		void notifyAlertReceived(short alertLevel, short alertDescription);

		/// <summary>
		/// Notifies the peer that the handshake has been successfully completed.
		/// </summary>
		void notifyHandshakeComplete();
	}

}