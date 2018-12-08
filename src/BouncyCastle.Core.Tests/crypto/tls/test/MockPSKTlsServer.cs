using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Strings = org.bouncycastle.util.Strings;

	public class MockPSKTlsServer : PSKTlsServer
	{
		public MockPSKTlsServer() : base(new MyIdentityManager())
		{
		}

		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
			PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			@out.println("TLS-PSK server raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
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
			@out.println("TLS-PSK server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
		}

		public override void notifyHandshakeComplete()
		{
			base.notifyHandshakeComplete();

			byte[] pskIdentity = context.getSecurityParameters().getPSKIdentity();
			if (pskIdentity != null)
			{
				string name = Strings.fromUTF8ByteArray(pskIdentity);
				JavaSystem.@out.println("TLS-PSK server completed handshake for PSK identity: " + name);
			}
		}

		public override int[] getCipherSuites()
		{
			return new int[]{CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA};
		}

		public override ProtocolVersion getMaximumVersion()
		{
			return ProtocolVersion.TLSv12;
		}

		public override ProtocolVersion getMinimumVersion()
		{
			return ProtocolVersion.TLSv12;
		}

		public override ProtocolVersion getServerVersion()
		{
			ProtocolVersion serverVersion = base.getServerVersion();

			JavaSystem.@out.println("TLS-PSK server negotiated " + serverVersion);

			return serverVersion;
		}

		public override TlsEncryptionCredentials getRSAEncryptionCredentials()
		{
			return TlsTestUtils.loadEncryptionCredentials(context, new string[]{"x509-server.pem", "x509-ca.pem"}, "x509-server-key.pem");
		}

		public class MyIdentityManager : TlsPSKIdentityManager
		{
			public virtual byte[] getHint()
			{
				return Strings.toUTF8ByteArray("hint");
			}

			public virtual byte[] getPSK(byte[] identity)
			{
				if (identity != null)
				{
					string name = Strings.fromUTF8ByteArray(identity);
					if (name.Equals("client"))
					{
						return new byte[16];
					}
				}
				return null;
			}
		}
	}

}