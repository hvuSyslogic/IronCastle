using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	public class SRPTlsServer : AbstractTlsServer
	{
		protected internal TlsSRPIdentityManager srpIdentityManager;

		protected internal byte[] srpIdentity = null;
		protected internal TlsSRPLoginParameters loginParameters = null;

		public SRPTlsServer(TlsSRPIdentityManager srpIdentityManager) : this(new DefaultTlsCipherFactory(), srpIdentityManager)
		{
		}

		public SRPTlsServer(TlsCipherFactory cipherFactory, TlsSRPIdentityManager srpIdentityManager) : base(cipherFactory)
		{
			this.srpIdentityManager = srpIdentityManager;
		}

		public virtual TlsSignerCredentials getDSASignerCredentials()
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public virtual TlsSignerCredentials getRSASignerCredentials()
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public override int[] getCipherSuites()
		{
			return new int[] {CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA};
		}

		public override void processClientExtensions(Hashtable clientExtensions)
		{
			base.processClientExtensions(clientExtensions);

			this.srpIdentity = TlsSRPUtils.getSRPExtension(clientExtensions);
		}

		public override int getSelectedCipherSuite()
		{
			int cipherSuite = base.getSelectedCipherSuite();

			if (TlsSRPUtils.isSRPCipherSuite(cipherSuite))
			{
				if (srpIdentity != null)
				{
					this.loginParameters = srpIdentityManager.getLoginParameters(srpIdentity);
				}

				if (loginParameters == null)
				{
					throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
				}
			}

			return cipherSuite;
		}

		public override TlsCredentials getCredentials()
		{
			int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

			switch (keyExchangeAlgorithm)
			{
			case KeyExchangeAlgorithm.SRP:
				return null;

			case KeyExchangeAlgorithm.SRP_DSS:
				return getDSASignerCredentials();

			case KeyExchangeAlgorithm.SRP_RSA:
				return getRSASignerCredentials();

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
			case KeyExchangeAlgorithm.SRP:
			case KeyExchangeAlgorithm.SRP_DSS:
			case KeyExchangeAlgorithm.SRP_RSA:
				return createSRPKeyExchange(keyExchangeAlgorithm);

			default:
				/*
				 * Note: internal error here; the TlsProtocol implementation verifies that the
				 * server-selected cipher suite was in the list of client-offered cipher suites, so if
				 * we now can't produce an implementation, we shouldn't have offered it!
				 */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public virtual TlsKeyExchange createSRPKeyExchange(int keyExchange)
		{
			return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, srpIdentity, loginParameters);
		}
	}

}