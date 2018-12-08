namespace org.bouncycastle.crypto.tls
{

	using DHStandardGroups = org.bouncycastle.crypto.agreement.DHStandardGroups;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;

	public class PSKTlsServer : AbstractTlsServer
	{
		protected internal TlsPSKIdentityManager pskIdentityManager;

		public PSKTlsServer(TlsPSKIdentityManager pskIdentityManager) : this(new DefaultTlsCipherFactory(), pskIdentityManager)
		{
		}

		public PSKTlsServer(TlsCipherFactory cipherFactory, TlsPSKIdentityManager pskIdentityManager) : base(cipherFactory)
		{
			this.pskIdentityManager = pskIdentityManager;
		}

		public virtual TlsEncryptionCredentials getRSAEncryptionCredentials()
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public virtual DHParameters getDHParameters()
		{
			return DHStandardGroups.rfc7919_ffdhe2048;
		}

		public override int[] getCipherSuites()
		{
			return new int[] {CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA};
		}

		public override TlsCredentials getCredentials()
		{
			int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

			switch (keyExchangeAlgorithm)
			{
			case KeyExchangeAlgorithm.DHE_PSK:
			case KeyExchangeAlgorithm.ECDHE_PSK:
			case KeyExchangeAlgorithm.PSK:
				return null;

			case KeyExchangeAlgorithm.RSA_PSK:
				return getRSAEncryptionCredentials();

			default:
				/* Note: internal error here; selected a key exchange we don't implement! */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
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

		public virtual TlsKeyExchange createPSKKeyExchange(int keyExchange)
		{
			return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, null, pskIdentityManager, null, getDHParameters(), namedCurves, clientECPointFormats, serverECPointFormats);
		}
	}

}