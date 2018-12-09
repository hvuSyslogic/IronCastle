﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	public abstract class AbstractTlsKeyExchange : TlsKeyExchange
	{
		public abstract byte[] generatePremasterSecret();
		public abstract void generateClientKeyExchange(OutputStream output);
		public abstract void processClientCredentials(TlsCredentials clientCredentials);
		public abstract void validateCertificateRequest(CertificateRequest certificateRequest);
		public abstract void skipServerCredentials();
		protected internal int keyExchange;
		protected internal Vector supportedSignatureAlgorithms;

		protected internal TlsContext context;

		public AbstractTlsKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms)
		{
			this.keyExchange = keyExchange;
			this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
		}

		public virtual DigitallySigned parseSignature(InputStream input)
		{
			DigitallySigned signature = DigitallySigned.parse(context, input);
			SignatureAndHashAlgorithm signatureAlgorithm = signature.getAlgorithm();
			if (signatureAlgorithm != null)
			{
				TlsUtils.verifySupportedSignatureAlgorithm(supportedSignatureAlgorithms, signatureAlgorithm);
			}
			return signature;
		}

		public virtual void init(TlsContext context)
		{
			this.context = context;

			ProtocolVersion clientVersion = context.getClientVersion();

			if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
			{
				/*
				 * RFC 5246 7.4.1.4.1. If the client does not send the signature_algorithms extension,
				 * the server MUST do the following:
				 * 
				 * - If the negotiated key exchange algorithm is one of (RSA, DHE_RSA, DH_RSA, RSA_PSK,
				 * ECDH_RSA, ECDHE_RSA), behave as if client had sent the value {sha1,rsa}.
				 * 
				 * - If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), behave as if
				 * the client had sent the value {sha1,dsa}.
				 * 
				 * - If the negotiated key exchange algorithm is one of (ECDH_ECDSA, ECDHE_ECDSA),
				 * behave as if the client had sent value {sha1,ecdsa}.
				 */
				if (this.supportedSignatureAlgorithms == null)
				{
					switch (keyExchange)
					{
					case KeyExchangeAlgorithm.DH_DSS:
					case KeyExchangeAlgorithm.DHE_DSS:
					case KeyExchangeAlgorithm.SRP_DSS:
					{
						this.supportedSignatureAlgorithms = TlsUtils.getDefaultDSSSignatureAlgorithms();
						break;
					}

					case KeyExchangeAlgorithm.ECDH_ECDSA:
					case KeyExchangeAlgorithm.ECDHE_ECDSA:
					{
						this.supportedSignatureAlgorithms = TlsUtils.getDefaultECDSASignatureAlgorithms();
						break;
					}

					case KeyExchangeAlgorithm.DH_RSA:
					case KeyExchangeAlgorithm.DHE_RSA:
					case KeyExchangeAlgorithm.ECDH_RSA:
					case KeyExchangeAlgorithm.ECDHE_RSA:
					case KeyExchangeAlgorithm.RSA:
					case KeyExchangeAlgorithm.RSA_PSK:
					case KeyExchangeAlgorithm.SRP_RSA:
					{
						this.supportedSignatureAlgorithms = TlsUtils.getDefaultRSASignatureAlgorithms();
						break;
					}

					case KeyExchangeAlgorithm.DHE_PSK:
					case KeyExchangeAlgorithm.ECDHE_PSK:
					case KeyExchangeAlgorithm.PSK:
					case KeyExchangeAlgorithm.SRP:
						break;

					default:
						throw new IllegalStateException("unsupported key exchange algorithm");
					}
				}
			}
			else if (this.supportedSignatureAlgorithms != null)
			{
				throw new IllegalStateException("supported_signature_algorithms not allowed for " + clientVersion);
			}
		}

		public virtual void processServerCertificate(Certificate serverCertificate)
		{
			if (supportedSignatureAlgorithms == null)
			{
				/*
				 * TODO RFC 2246 7.4.2. Unless otherwise specified, the signing algorithm for the
				 * certificate must be the same as the algorithm for the certificate key.
				 */
			}
			else
			{
				/*
				 * TODO RFC 5246 7.4.2. If the client provided a "signature_algorithms" extension, then
				 * all certificates provided by the server MUST be signed by a hash/signature algorithm
				 * pair that appears in that extension.
				 */
			}
		}

		public virtual void processServerCredentials(TlsCredentials serverCredentials)
		{
			processServerCertificate(serverCredentials.getCertificate());
		}

		public virtual bool requiresServerKeyExchange()
		{
			return false;
		}

		public virtual byte[] generateServerKeyExchange()
		{
			if (requiresServerKeyExchange())
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
			return null;
		}

		public virtual void skipServerKeyExchange()
		{
			if (requiresServerKeyExchange())
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void processServerKeyExchange(InputStream input)
		{
			if (!requiresServerKeyExchange())
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void skipClientCredentials()
		{
		}

		public virtual void processClientCertificate(Certificate clientCertificate)
		{
		}

		public virtual void processClientKeyExchange(InputStream input)
		{
			// Key exchange implementation MUST support client key exchange
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}
	}

}