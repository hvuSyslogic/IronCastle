using org.bouncycastle.crypto.tls;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;

	public class TlsTestServerImpl : DefaultTlsServer
	{
		protected internal readonly TlsTestConfig config;

		protected internal int firstFatalAlertConnectionEnd = -1;
		protected internal short firstFatalAlertDescription = -1;

		public TlsTestServerImpl(TlsTestConfig config)
		{
			this.config = config;
		}

		public virtual int getFirstFatalAlertConnectionEnd()
		{
			return firstFatalAlertConnectionEnd;
		}

		public virtual short getFirstFatalAlertDescription()
		{
			return firstFatalAlertDescription;
		}

		public override ProtocolVersion getMaximumVersion()
		{
			if (config.serverMaximumVersion != null)
			{
				return config.serverMaximumVersion;
			}

			return base.getMaximumVersion();
		}

		public override ProtocolVersion getMinimumVersion()
		{
			if (config.serverMinimumVersion != null)
			{
				return config.serverMinimumVersion;
			}

			return base.getMinimumVersion();
		}

		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
			if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
			{
				firstFatalAlertConnectionEnd = ConnectionEnd.server;
				firstFatalAlertDescription = alertDescription;
			}

			if (TlsTestConfig.DEBUG)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
				if (!string.ReferenceEquals(message, null))
				{
					@out.println("> " + message);
				}
				if (cause != null)
				{
					cause.printStackTrace(@out);
				}
			}
		}

		public override void notifyAlertReceived(short alertLevel, short alertDescription)
		{
			if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
			{
				firstFatalAlertConnectionEnd = ConnectionEnd.client;
				firstFatalAlertDescription = alertDescription;
			}

			if (TlsTestConfig.DEBUG)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
			}
		}

		public override ProtocolVersion getServerVersion()
		{
			ProtocolVersion serverVersion = base.getServerVersion();

			if (TlsTestConfig.DEBUG)
			{
				JavaSystem.@out.println("TLS server negotiated " + serverVersion);
			}

			return serverVersion;
		}

		public override CertificateRequest getCertificateRequest()
		{
			if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
			{
				return null;
			}

			short[] certificateTypes = new short[]{ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign};

			Vector serverSigAlgs = null;
			if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
			{
				serverSigAlgs = config.serverCertReqSigAlgs;
				if (serverSigAlgs == null)
				{
					serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
				}
			}

			Vector certificateAuthorities = new Vector();
			certificateAuthorities.addElement(TlsTestUtils.loadCertificateResource("x509-ca.pem").getSubject());

			return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
		}

		public override void notifyClientCertificate(Certificate clientCertificate)
		{
			bool isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

			if (isEmpty != (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE))
			{
				throw new IllegalStateException();
			}
			if (isEmpty && (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_MANDATORY))
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}

			Certificate[] chain = clientCertificate.getCertificateList();

			// TODO Cache test resources?
			if (!isEmpty && !(chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-client.pem")) || chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-client-dsa.pem")) || chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-client-ecdsa.pem"))))
			{
				throw new TlsFatalAlert(AlertDescription.bad_certificate);
			}

			if (TlsTestConfig.DEBUG)
			{
				JavaSystem.@out.println("TLS server received client certificate chain of length " + chain.Length);
				for (int i = 0; i != chain.Length; i++)
				{
					Certificate entry = chain[i];
					// TODO Create fingerprint based on certificate signature algorithm digest
					JavaSystem.@out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject() + ")");
				}
			}
		}

		public virtual Vector getSupportedSignatureAlgorithms()
		{
			if (TlsUtils.isTLSv12(context) && config.serverAuthSigAlg != null)
			{
				Vector signatureAlgorithms = new Vector(1);
				signatureAlgorithms.addElement(config.serverAuthSigAlg);
				return signatureAlgorithms;
			}

			return supportedSignatureAlgorithms;
		}

		public override TlsSignerCredentials getDSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.dsa, "x509-server-dsa.pem", "x509-server-key-dsa.pem");
		}

		public override TlsSignerCredentials getECDSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.ecdsa, "x509-server-ecdsa.pem", "x509-server-key-ecdsa.pem");
		}

		public override TlsEncryptionCredentials getRSAEncryptionCredentials()
		{
			return TlsTestUtils.loadEncryptionCredentials(context, new string[]{"x509-server.pem", "x509-ca.pem"}, "x509-server-key.pem");
		}

		public override TlsSignerCredentials getRSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.rsa, "x509-server.pem", "x509-server-key.pem");
		}
	}
}