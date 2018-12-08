using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.tls
{

	using RandomGenerator = org.bouncycastle.crypto.prng.RandomGenerator;

	public interface TlsContext
	{
		RandomGenerator getNonceRandomGenerator();

		SecureRandom getSecureRandom();

		SecurityParameters getSecurityParameters();

		bool isServer();

		ProtocolVersion getClientVersion();

		ProtocolVersion getServerVersion();

		/// <summary>
		/// Used to get the resumable session, if any, used by this connection. Only available after the
		/// handshake has successfully completed.
		/// </summary>
		/// <returns> A <seealso cref="TlsSession"/> representing the resumable session used by this connection, or
		///         null if no resumable session available. </returns>
		/// <seealso cref= TlsPeer#notifyHandshakeComplete() </seealso>
		TlsSession getResumableSession();

		object getUserObject();

		void setUserObject(object userObject);

		/// <summary>
		/// Export keying material according to RFC 5705: "Keying Material Exporters for TLS".
		/// </summary>
		/// <param name="asciiLabel">    indicates which application will use the exported keys. </param>
		/// <param name="context_value"> allows the application using the exporter to mix its own data with the TLS PRF for
		///                      the exporter output. </param>
		/// <param name="length">        the number of bytes to generate </param>
		/// <returns> a pseudorandom bit string of 'length' bytes generated from the master_secret. </returns>
		byte[] exportKeyingMaterial(string asciiLabel, byte[] context_value, int length);
	}

}