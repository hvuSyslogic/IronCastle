namespace org.bouncycastle.crypto.tls
{

	public class PSKTlsClient : AbstractTlsClient
	{
		protected internal TlsDHVerifier dhVerifier;
		protected internal TlsPSKIdentity pskIdentity;

		public PSKTlsClient(TlsPSKIdentity pskIdentity) : this(new DefaultTlsCipherFactory(), pskIdentity)
		{
		}

		public PSKTlsClient(TlsCipherFactory cipherFactory, TlsPSKIdentity pskIdentity) : this(cipherFactory, new DefaultTlsDHVerifier(), pskIdentity)
		{
		}

		public PSKTlsClient(TlsCipherFactory cipherFactory, TlsDHVerifier dhVerifier, TlsPSKIdentity pskIdentity) : base(cipherFactory)
		{

			this.dhVerifier = dhVerifier;
			this.pskIdentity = pskIdentity;
		}

		public override int[] getCipherSuites()
		{
			return new int[] {CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA};
		}

		public override TlsKeyExchange getKeyExchange()
		{
			int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

			switch (keyExchangeAlgorithm)
			{
			case KeyExchangeAlgorithm.DHE_PSK:
			case KeyExchangeAlgorithm.ECDHE_PSK:
			case KeyExchangeAlgorithm.PSK:
			case KeyExchangeAlgorithm.RSA_PSK:
				return createPSKKeyExchange(keyExchangeAlgorithm);

			default:
				/*
				 * Note: internal error here; the TlsProtocol implementation verifies that the
				 * server-selected cipher suite was in the list of client-offered cipher suites, so if
				 * we now can't produce an implementation, we shouldn't have offered it!
				 */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public override TlsAuthentication getAuthentication()
		{
			/*
			 * Note: This method is not called unless a server certificate is sent, which may be the
			 * case e.g. for RSA_PSK key exchange.
			 */
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public virtual TlsKeyExchange createPSKKeyExchange(int keyExchange)
		{
			return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, null, dhVerifier, null, namedCurves, clientECPointFormats, serverECPointFormats);
		}
	}

}