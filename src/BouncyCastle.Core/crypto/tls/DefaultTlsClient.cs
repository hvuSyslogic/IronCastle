namespace org.bouncycastle.crypto.tls
{

	public abstract class DefaultTlsClient : AbstractTlsClient
	{
		protected internal TlsDHVerifier dhVerifier;

		public DefaultTlsClient() : this(new DefaultTlsCipherFactory())
		{
		}

		public DefaultTlsClient(TlsCipherFactory cipherFactory) : this(cipherFactory, new DefaultTlsDHVerifier())
		{
		}

		public DefaultTlsClient(TlsCipherFactory cipherFactory, TlsDHVerifier dhVerifier) : base(cipherFactory)
		{

			this.dhVerifier = dhVerifier;
		}

		public override int[] getCipherSuites()
		{
			return new int[] {CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA};
		}

		public override TlsKeyExchange getKeyExchange()
		{
			int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

			switch (keyExchangeAlgorithm)
			{
			case KeyExchangeAlgorithm.DH_anon:
			case KeyExchangeAlgorithm.DH_DSS:
			case KeyExchangeAlgorithm.DH_RSA:
				return createDHKeyExchange(keyExchangeAlgorithm);

			case KeyExchangeAlgorithm.DHE_DSS:
			case KeyExchangeAlgorithm.DHE_RSA:
				return createDHEKeyExchange(keyExchangeAlgorithm);

			case KeyExchangeAlgorithm.ECDH_anon:
			case KeyExchangeAlgorithm.ECDH_ECDSA:
			case KeyExchangeAlgorithm.ECDH_RSA:
				return createECDHKeyExchange(keyExchangeAlgorithm);

			case KeyExchangeAlgorithm.ECDHE_ECDSA:
			case KeyExchangeAlgorithm.ECDHE_RSA:
				return createECDHEKeyExchange(keyExchangeAlgorithm);

			case KeyExchangeAlgorithm.RSA:
				return createRSAKeyExchange();

			default:
				/*
				 * Note: internal error here; the TlsProtocol implementation verifies that the
				 * server-selected cipher suite was in the list of client-offered cipher suites, so if
				 * we now can't produce an implementation, we shouldn't have offered it!
				 */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public virtual TlsKeyExchange createDHKeyExchange(int keyExchange)
		{
			return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, dhVerifier, null);
		}

		public virtual TlsKeyExchange createDHEKeyExchange(int keyExchange)
		{
			return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, dhVerifier, null);
		}

		public virtual TlsKeyExchange createECDHKeyExchange(int keyExchange)
		{
			return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
		}

		public virtual TlsKeyExchange createECDHEKeyExchange(int keyExchange)
		{
			return new TlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
		}

		public virtual TlsKeyExchange createRSAKeyExchange()
		{
			return new TlsRSAKeyExchange(supportedSignatureAlgorithms);
		}
	}

}