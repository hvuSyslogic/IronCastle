using org.bouncycastle.crypto.tls;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Arrays = org.bouncycastle.util.Arrays;

	public class MockTlsServer : DefaultTlsServer
	{
		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
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

		public override void notifyAlertReceived(short alertLevel, short alertDescription)
		{
			PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			@out.println("TLS server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
		}

		public override int[] getCipherSuites()
		{
			return Arrays.concatenate(base.getCipherSuites(), new int[] {CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256});
		}

		public override ProtocolVersion getMaximumVersion()
		{
			return ProtocolVersion.TLSv12;
		}

		public override ProtocolVersion getServerVersion()
		{
			ProtocolVersion serverVersion = base.getServerVersion();

			JavaSystem.@out.println("TLS server negotiated " + serverVersion);

			return serverVersion;
		}

		public override CertificateRequest getCertificateRequest()
		{
			short[] certificateTypes = new short[]{ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign};

			Vector serverSigAlgs = null;
			if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
			{
				serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
			}

			Vector certificateAuthorities = new Vector();
			certificateAuthorities.addElement(TlsTestUtils.loadCertificateResource("x509-ca.pem").getSubject());

			return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
		}

		public override void notifyClientCertificate(Certificate clientCertificate)
		{
			Certificate[] chain = clientCertificate.getCertificateList();
			JavaSystem.@out.println("TLS server received client certificate chain of length " + chain.Length);
			for (int i = 0; i != chain.Length; i++)
			{
				Certificate entry = chain[i];
				// TODO Create fingerprint based on certificate signature algorithm digest
				JavaSystem.@out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject() + ")");
			}
		}

		public override TlsEncryptionCredentials getRSAEncryptionCredentials()
		{
			return TlsTestUtils.loadEncryptionCredentials(context, new string[]{"x509-server.pem", "x509-ca.pem"}, "x509-server-key.pem");
		}

		public override TlsSignerCredentials getRSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa, "x509-server.pem", "x509-server-key.pem");
		}
	}
}