using System;

namespace org.bouncycastle.crypto.tls.test
{

	using SRP6StandardGroups = org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
	using SRP6VerifierGenerator = org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	public class MockSRPTlsServer : SRPTlsServer
	{
		internal static readonly SRP6GroupParameters TEST_GROUP = SRP6StandardGroups.rfc5054_1024;
		internal static readonly byte[] TEST_IDENTITY = Strings.toUTF8ByteArray("client");
		internal static readonly byte[] TEST_PASSWORD = Strings.toUTF8ByteArray("password");
		internal static readonly byte[] TEST_SALT = Strings.toUTF8ByteArray("salt");
		internal static readonly byte[] TEST_SEED_KEY = Strings.toUTF8ByteArray("seed_key");

		public MockSRPTlsServer() : base(new MyIdentityManager())
		{
		}

		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
			PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			@out.println("TLS-SRP server raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
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
			@out.println("TLS-SRP server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
		}

		public override void notifyHandshakeComplete()
		{
			base.notifyHandshakeComplete();

			byte[] srpIdentity = context.getSecurityParameters().getSRPIdentity();
			if (srpIdentity != null)
			{
				string name = Strings.fromUTF8ByteArray(srpIdentity);
				JavaSystem.@out.println("TLS-SRP server completed handshake for SRP identity: " + name);
			}
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

			JavaSystem.@out.println("TLS-SRP server negotiated " + serverVersion);

			return serverVersion;
		}

		public override TlsSignerCredentials getDSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.dsa, "x509-server-dsa.pem", "x509-server-key-dsa.pem");
		}

		public override TlsSignerCredentials getRSASignerCredentials()
		{
			return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa, "x509-server.pem", "x509-server-key.pem");
		}

		public class MyIdentityManager : TlsSRPIdentityManager
		{
			protected internal SimulatedTlsSRPIdentityManager unknownIdentityManager = SimulatedTlsSRPIdentityManager.getRFC5054Default(TEST_GROUP, TEST_SEED_KEY);

			public virtual TlsSRPLoginParameters getLoginParameters(byte[] identity)
			{
				if (Arrays.areEqual(TEST_IDENTITY, identity))
				{
					SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
					verifierGenerator.init(TEST_GROUP, TlsUtils.createHash(HashAlgorithm.sha1));

					BigInteger verifier = verifierGenerator.generateVerifier(TEST_SALT, identity, TEST_PASSWORD);

					return new TlsSRPLoginParameters(TEST_GROUP, verifier, TEST_SALT);
				}

				return unknownIdentityManager.getLoginParameters(identity);
			}
		}
	}

}