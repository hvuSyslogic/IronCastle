using org.bouncycastle.crypto.tls;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class MockSRPTlsClient : SRPTlsClient
	{
		internal TlsSession session;

		public MockSRPTlsClient(TlsSession session, byte[] identity, byte[] password) : base(identity, password)
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
			@out.println("TLS-SRP client raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
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
			@out.println("TLS-SRP client received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
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

		public override ProtocolVersion getMinimumVersion()
		{
			return ProtocolVersion.TLSv12;
		}

		public override Hashtable getClientExtensions()
		{
			Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(base.getClientExtensions());
			TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
			return clientExtensions;
		}

		public override void notifyServerVersion(ProtocolVersion serverVersion)
		{
			base.notifyServerVersion(serverVersion);

			JavaSystem.@out.println("TLS-SRP client negotiated " + serverVersion);
		}

		public override TlsAuthentication getAuthentication()
		{
			return new ServerOnlyTlsAuthenticationAnonymousInnerClass(this);
		}

		public class ServerOnlyTlsAuthenticationAnonymousInnerClass : ServerOnlyTlsAuthentication
		{
			private readonly MockSRPTlsClient outerInstance;

			public ServerOnlyTlsAuthenticationAnonymousInnerClass(MockSRPTlsClient outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public override void notifyServerCertificate(Certificate serverCertificate)
			{
				Certificate[] chain = serverCertificate.getCertificateList();
				JavaSystem.@out.println("TLS-SRP client received server certificate chain of length " + chain.Length);
				for (int i = 0; i != chain.Length; i++)
				{
					Certificate entry = chain[i];
					// TODO Create fingerprint based on certificate signature algorithm digest
					JavaSystem.@out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject() + ")");
				}
			}
		}
	}

}