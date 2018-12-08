namespace org.bouncycastle.crypto.tls
{

	public interface TlsHandshakeHash : Digest
	{
		void init(TlsContext context);

		TlsHandshakeHash notifyPRFDetermined();

		void trackHashAlgorithm(short hashAlgorithm);

		void sealHashAlgorithms();

		TlsHandshakeHash stopTracking();

		Digest forkPRFHash();

		byte[] getFinalHash(short hashAlgorithm);
	}

}