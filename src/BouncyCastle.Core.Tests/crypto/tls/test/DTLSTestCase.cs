using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Arrays = org.bouncycastle.util.Arrays;

	using TestCase = junit.framework.TestCase;

	public class DTLSTestCase : TestCase
	{
		private static void checkDTLSVersion(ProtocolVersion version)
		{
			if (version != null && !version.isDTLS())
			{
				throw new IllegalStateException("Non-DTLS version");
			}
		}

		protected internal readonly TlsTestConfig config;

		public DTLSTestCase(string name) : base(name)
		{

			this.config = null;
		}

		public DTLSTestCase(TlsTestConfig config, string name) : base(name)
		{

			checkDTLSVersion(config.clientMinimumVersion);
			checkDTLSVersion(config.clientOfferVersion);
			checkDTLSVersion(config.serverMaximumVersion);
			checkDTLSVersion(config.serverMinimumVersion);

			this.config = config;
		}

		public virtual void testDummy()
		{
			// Avoid "No tests found" warning from junit
		}

		public virtual void runTest()
		{
			// Disable the test if it is not being run via DTLSTestSuite
			if (config == null)
			{
				return;
			}

			SecureRandom secureRandom = new SecureRandom();

			DTLSTestClientProtocol clientProtocol = new DTLSTestClientProtocol(secureRandom, config);
			DTLSTestServerProtocol serverProtocol = new DTLSTestServerProtocol(secureRandom, config);

			MockDatagramAssociation network = new MockDatagramAssociation(1500);

			TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
			TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

			ServerThread serverThread = new ServerThread(this, serverProtocol, network.getServer(), serverImpl);
			serverThread.start();

			Exception caught = null;
			try
			{
				DatagramTransport clientTransport = network.getClient();

				if (TlsTestConfig.DEBUG)
				{
					clientTransport = new LoggingDatagramTransport(clientTransport, System.out);
				}

				DTLSTransport dtlsClient = clientProtocol.connect(clientImpl, clientTransport);

				for (int i = 1; i <= 10; ++i)
				{
					byte[] data = new byte[i];
					Arrays.fill(data, (byte)i);
					dtlsClient.send(data, 0, data.Length);
				}

				byte[] buf = new byte[dtlsClient.getReceiveLimit()];
				while (dtlsClient.receive(buf, 0, buf.Length, 100) >= 0)
				{
				}

				dtlsClient.close();
			}
			catch (Exception e)
			{
				caught = e;
				logException(caught);
			}

			serverThread.shutdown();

			// TODO Add checks that the various streams were closed

			assertEquals("Client fatal alert connection end", config.expectFatalAlertConnectionEnd, clientImpl.firstFatalAlertConnectionEnd);
			assertEquals("Server fatal alert connection end", config.expectFatalAlertConnectionEnd, serverImpl.firstFatalAlertConnectionEnd);

			assertEquals("Client fatal alert description", config.expectFatalAlertDescription, clientImpl.firstFatalAlertDescription);
			assertEquals("Server fatal alert description", config.expectFatalAlertDescription, serverImpl.firstFatalAlertDescription);

			if (config.expectFatalAlertConnectionEnd == -1)
			{
				assertNull("Unexpected client exception", caught);
				assertNull("Unexpected server exception", serverThread.caught);
			}
		}

		public virtual void logException(Exception e)
		{
			if (TlsTestConfig.DEBUG)
			{
				Console.WriteLine(e.ToString());
				Console.Write(e.StackTrace);
			}
		}

		public class ServerThread : Thread
		{
			private readonly DTLSTestCase outerInstance;

			internal readonly DTLSTestServerProtocol serverProtocol;
			internal readonly DatagramTransport serverTransport;
			internal readonly TlsTestServerImpl serverImpl;

			internal volatile bool isShutdown = false;
			internal Exception caught = null;

			public ServerThread(DTLSTestCase outerInstance, DTLSTestServerProtocol serverProtocol, DatagramTransport serverTransport, TlsTestServerImpl serverImpl)
			{
				this.outerInstance = outerInstance;
				this.serverProtocol = serverProtocol;
				this.serverTransport = serverTransport;
				this.serverImpl = serverImpl;
			}

			public virtual void run()
			{
				try
				{
					DTLSTransport dtlsServer = serverProtocol.accept(serverImpl, serverTransport);
					byte[] buf = new byte[dtlsServer.getReceiveLimit()];
					while (!isShutdown)
					{
						int length = dtlsServer.receive(buf, 0, buf.Length, 100);
						if (length >= 0)
						{
							dtlsServer.send(buf, 0, length);
						}
					}
					dtlsServer.close();
				}
				catch (Exception e)
				{
					caught = e;
					outerInstance.logException(caught);
				}
			}

			public virtual void shutdown()
			{
				if (!isShutdown)
				{
					isShutdown = true;
					this.interrupt();
					this.join();
				}
			}
		}
	}

}