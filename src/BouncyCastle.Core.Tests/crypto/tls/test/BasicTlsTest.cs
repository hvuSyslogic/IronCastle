using org.bouncycastle.asn1.x509;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class BasicTlsTest : TestCase
	{
		private const int PORT_NO = 8003;

		public virtual bool isSufficientVMVersion(string vmVersion)
		{
			if (string.ReferenceEquals(vmVersion, null))
			{
				return false;
			}
			string[] parts = vmVersion.Split(@"\.", true);
			if (parts == null || parts.Length != 2)
			{
				return false;
			}
			try
			{
				int major = int.Parse(parts[0]);
				if (major != 1)
				{
					return major > 1;
				}
				int minor = int.Parse(parts[1]);
				return minor >= 7;
			}
			catch (NumberFormatException)
			{
				return false;
			}
		}

		public virtual void testConnection()
		{
			string vmVersion = System.getProperty("java.specification.version");
			if (!isSufficientVMVersion(vmVersion))
			{
				return; // only works on later VMs.
			}

			Thread server = new HTTPSServerThread();

			server.start();

			Thread.yield();

			Socket s = null;

			for (int i = 0; s == null && i != 3; i++)
			{
				Thread.sleep(1000);

				try
				{
					s = new Socket("localhost", PORT_NO);
				}
				catch (IOException)
				{
					// ignore
				}
			}

			if (s == null)
			{
				throw new IOException("unable to connect");
			}

			TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream(), new SecureRandom());
			protocol.connect(new MyTlsClient(new ServerOnlyTlsAuthenticationAnonymousInnerClass(this)));

			InputStream @is = protocol.getInputStream();
			OutputStream os = protocol.getOutputStream();

			os.write("GET / HTTP/1.1\r\n\r\n".GetBytes());

			byte[] buf = new byte[4096];
			int read = 0;
			int total = 0;

			while ((read = @is.read(buf, total, buf.Length - total)) > 0)
			{
				total += read;
			}

			@is.close();

			byte[] expected = Hex.decode("485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a20746578742f68" + "746d6c0d0a0d0a3c68746d6c3e0d0a3c626f64793e0d0a48656c6c6f20576f726c64210d0a3c2f626f64793e0d0a3c2f" + "68746d6c3e0d0a");
			assertEquals(total, expected.Length);

			byte[] tmp = new byte[expected.Length];
			JavaSystem.arraycopy(buf, 0, tmp, 0, total);
			assertTrue(Arrays.areEqual(expected, tmp));
		}

		public class ServerOnlyTlsAuthenticationAnonymousInnerClass : ServerOnlyTlsAuthentication
		{
			private readonly BasicTlsTest outerInstance;

			public ServerOnlyTlsAuthenticationAnonymousInnerClass(BasicTlsTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public override void notifyServerCertificate(Certificate serverCertificate)
			{
				// NOTE: In production code this MUST verify the certificate!
			}
		}

		public virtual void testRSAConnectionClient()
		{
			MyTlsClient client = new MyTlsClient(null);

			checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsTestUtils.rsaCertData);
			checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TlsTestUtils.rsaCertData);
			checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, TlsTestUtils.rsaCertData);
			checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, TlsTestUtils.rsaCertData);

			try
			{
				checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsTestUtils.dudRsaCertData);

				fail("dud certificate not caught");
			}
			catch (TlsFatalAlert e)
			{
				assertEquals(AlertDescription.certificate_unknown, e.getAlertDescription());
			}

			try
			{
				checkConnectionClient(client, CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TlsTestUtils.rsaCertData);

				fail("wrong certificate not caught");
			}
			catch (TlsFatalAlert e)
			{
				assertEquals(AlertDescription.internal_error, e.getAlertDescription());
			}
		}

		private void checkConnectionClient(TlsClient client, int cipherSuite, byte[] encCert)
		{
			client.notifySelectedCipherSuite(cipherSuite);

			TlsKeyExchange keyExchange = client.getKeyExchange();

			keyExchange.processServerCertificate(new Certificate(new Certificate[]{Certificate.getInstance(encCert)}));
		}

		public static TestSuite suite()
		{
			return new TestSuite(typeof(BasicTlsTest));
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(suite());
		}

		public class MyTlsClient : DefaultTlsClient
		{
			public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription + ")");
				if (!string.ReferenceEquals(message, null))
				{
					@out.println(message);
				}
				if (cause != null)
				{
					cause.printStackTrace(@out);
				}
			}

			public override void notifyAlertReceived(short alertLevel, short alertDescription)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription + ")");
			}

			internal readonly TlsAuthentication authentication;

			public MyTlsClient(TlsAuthentication authentication)
			{
				this.authentication = authentication;
			}

			public override TlsAuthentication getAuthentication()
			{
				return authentication;
			}
		}
	}

}