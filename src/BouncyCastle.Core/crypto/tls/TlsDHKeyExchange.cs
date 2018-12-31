using org.bouncycastle.asn1.x509;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

							
	/// <summary>
	/// (D)TLS DH key exchange.
	/// </summary>
	public class TlsDHKeyExchange : AbstractTlsKeyExchange
	{
		protected internal TlsSigner tlsSigner;
		protected internal TlsDHVerifier dhVerifier;
		protected internal DHParameters dhParameters;

		protected internal AsymmetricKeyParameter serverPublicKey;
		protected internal TlsAgreementCredentials agreementCredentials;

		protected internal DHPrivateKeyParameters dhAgreePrivateKey;
		protected internal DHPublicKeyParameters dhAgreePublicKey;

		/// @deprecated Use constructor that takes a TlsDHVerifier 
		public TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters) : this(keyExchange, supportedSignatureAlgorithms, new DefaultTlsDHVerifier(), dhParameters)
		{
		}

		public TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHVerifier dhVerifier, DHParameters dhParameters) : base(keyExchange, supportedSignatureAlgorithms)
		{

			switch (keyExchange)
			{
			case KeyExchangeAlgorithm.DH_anon:
			case KeyExchangeAlgorithm.DH_RSA:
			case KeyExchangeAlgorithm.DH_DSS:
				this.tlsSigner = null;
				break;
			case KeyExchangeAlgorithm.DHE_RSA:
				this.tlsSigner = new TlsRSASigner();
				break;
			case KeyExchangeAlgorithm.DHE_DSS:
				this.tlsSigner = new TlsDSSSigner();
				break;
			default:
				throw new IllegalArgumentException("unsupported key exchange algorithm");
			}

			this.dhVerifier = dhVerifier;
			this.dhParameters = dhParameters;
		}

		public override void init(TlsContext context)
		{
			base.init(context);

			if (this.tlsSigner != null)
			{
				this.tlsSigner.init(context);
			}
		}

		public override void skipServerCredentials()
		{
			if (keyExchange != KeyExchangeAlgorithm.DH_anon)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public override void processServerCertificate(Certificate serverCertificate)
		{
			if (keyExchange == KeyExchangeAlgorithm.DH_anon)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
			if (serverCertificate.isEmpty())
			{
				throw new TlsFatalAlert(AlertDescription.bad_certificate);
			}

		    org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

			SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
			try
			{
				this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
			}
			catch (RuntimeException e)
			{
				throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
			}

			if (tlsSigner == null)
			{
				try
				{
					this.dhAgreePublicKey = (DHPublicKeyParameters)this.serverPublicKey;
					this.dhParameters = dhAgreePublicKey.getParameters();
				}
				catch (ClassCastException e)
				{
					throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
				}

				TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyAgreement);
			}
			else
			{
				if (!tlsSigner.isValidPublicKey(this.serverPublicKey))
				{
					throw new TlsFatalAlert(AlertDescription.certificate_unknown);
				}

				TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
			}

			base.processServerCertificate(serverCertificate);
		}

		public override bool requiresServerKeyExchange()
		{
			switch (keyExchange)
			{
			case KeyExchangeAlgorithm.DH_anon:
			case KeyExchangeAlgorithm.DHE_DSS:
			case KeyExchangeAlgorithm.DHE_RSA:
				return true;
			default:
				return false;
			}
		}

		public override byte[] generateServerKeyExchange()
		{
			if (!requiresServerKeyExchange())
			{
				return null;
			}

			// DH_anon is handled here, DHE_* in a subclass

			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(), this.dhParameters, buf);
			return buf.toByteArray();
		}

		public override void processServerKeyExchange(InputStream input)
		{
			if (!requiresServerKeyExchange())
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}

			// DH_anon is handled here, DHE_* in a subclass

			this.dhParameters = TlsDHUtils.receiveDHParameters(dhVerifier, input);
			this.dhAgreePublicKey = new DHPublicKeyParameters(TlsDHUtils.readDHParameter(input), dhParameters);
		}

		public override void validateCertificateRequest(CertificateRequest certificateRequest)
		{
			if (keyExchange == KeyExchangeAlgorithm.DH_anon)
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}

			short[] types = certificateRequest.getCertificateTypes();
			for (int i = 0; i < types.Length; ++i)
			{
				switch (types[i])
				{
				case ClientCertificateType.rsa_sign:
				case ClientCertificateType.dss_sign:
				case ClientCertificateType.rsa_fixed_dh:
				case ClientCertificateType.dss_fixed_dh:
				case ClientCertificateType.ecdsa_sign:
					break;
				default:
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
			}
		}

		public override void processClientCredentials(TlsCredentials clientCredentials)
		{
			if (keyExchange == KeyExchangeAlgorithm.DH_anon)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			if (clientCredentials is TlsAgreementCredentials)
			{
				// TODO Validate client cert has matching parameters (see 'areCompatibleParameters')?

				this.agreementCredentials = (TlsAgreementCredentials)clientCredentials;
			}
			else if (clientCredentials is TlsSignerCredentials)
			{
				// OK
			}
			else
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public override void generateClientKeyExchange(OutputStream output)
		{
			/*
			 * RFC 2246 7.4.7.2 If the client certificate already contains a suitable Diffie-Hellman
			 * key, then Yc is implicit and does not need to be sent again. In this case, the Client Key
			 * Exchange message will be sent, but will be empty.
			 */
			if (agreementCredentials == null)
			{
				this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(context.getSecureRandom(), dhParameters, output);
			}
		}

		public override void processClientCertificate(Certificate clientCertificate)
		{
			if (keyExchange == KeyExchangeAlgorithm.DH_anon)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}

			// TODO Extract the public key
			// TODO If the certificate is 'fixed', take the public key as dhAgreePublicKey
		}

		public override void processClientKeyExchange(InputStream input)
		{
			if (dhAgreePublicKey != null)
			{
				// For dss_fixed_dh and rsa_fixed_dh, the key arrived in the client certificate
				return;
			}

			this.dhAgreePublicKey = new DHPublicKeyParameters(TlsDHUtils.readDHParameter(input), dhParameters);
		}

		public override byte[] generatePremasterSecret()
		{
			if (agreementCredentials != null)
			{
				return agreementCredentials.generateAgreement(dhAgreePublicKey);
			}

			if (dhAgreePrivateKey != null)
			{
				return TlsDHUtils.calculateDHBasicAgreement(dhAgreePublicKey, dhAgreePrivateKey);
			}

			throw new TlsFatalAlert(AlertDescription.internal_error);
		}
	}

}