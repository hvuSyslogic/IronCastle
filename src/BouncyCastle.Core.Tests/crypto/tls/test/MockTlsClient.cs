using org.bouncycastle.crypto.tls;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class MockTlsClient : DefaultTlsClient
	{
		internal TlsSession session;

		public MockTlsClient(TlsSession session)
		{
			this.session = session;
		}

		public override TlsSession getSessionToResume()
		{
			return this.session;
		}

		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
			PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			@out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
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
			@out.println("TLS client received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
		}

	//    public int[] getCipherSuites()
	//    {
	//        return Arrays.concatenate(super.getCipherSuites(),
	//            new int[]
	//            {
	//                CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	//            });
	//    }

		public override Hashtable getClientExtensions()
		{
			Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(base.getClientExtensions());
			TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
			{
				/*
				 * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
				 */
				TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
				TlsExtensionsUtils.addPaddingExtension(clientExtensions, context.getSecureRandom().nextInt(16));
				TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
			}
			return clientExtensions;
		}

		public override void notifyServerVersion(ProtocolVersion serverVersion)
		{
			base.notifyServerVersion(serverVersion);

			JavaSystem.@out.println("TLS client negotiated " + serverVersion);
		}

		public override TlsAuthentication getAuthentication()
		{
			return new TlsAuthenticationAnonymousInnerClass(this);
		}

		public class TlsAuthenticationAnonymousInnerClass : TlsAuthentication
		{
			private readonly MockTlsClient outerInstance;

			public TlsAuthenticationAnonymousInnerClass(MockTlsClient outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public void notifyServerCertificate(Certificate serverCertificate)
			{
				Certificate[] chain = serverCertificate.getCertificateList();
				JavaSystem.@out.println("TLS client received server certificate chain of length " + chain.Length);
				for (int i = 0; i != chain.Length; i++)
				{
					Certificate entry = chain[i];
					// TODO Create fingerprint based on certificate signature algorithm digest
					JavaSystem.@out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject() + ")");
				}
			}

			public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
			{
				short[] certificateTypes = certificateRequest.getCertificateTypes();
				if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
				{
					return null;
				}

				return TlsTestUtils.loadSignerCredentials(outerInstance.context, certificateRequest.getSupportedSignatureAlgorithms(), SignatureAlgorithm.rsa, "x509-client.pem", "x509-client-key.pem");
			}
		}

		public override void notifyHandshakeComplete()
		{
			base.notifyHandshakeComplete();

			TlsSession newSession = context.getResumableSession();
			if (newSession != null)
			{
				byte[] newSessionID = newSession.getSessionID();
				string hex = Hex.toHexString(newSessionID);

				if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
				{
					JavaSystem.@out.println("Resumed session: " + hex);
				}
				else
				{
					JavaSystem.@out.println("Established session: " + hex);
				}

				this.session = newSession;
			}
		}
	}

}