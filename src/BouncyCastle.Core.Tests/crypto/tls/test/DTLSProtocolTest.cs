using System;

namespace org.bouncycastle.crypto.tls.test
{

	using TestCase = junit.framework.TestCase;

	using Arrays = org.bouncycastle.util.Arrays;

	public class DTLSProtocolTest : TestCase
	{
		public virtual void testClientServer()
		{
			SecureRandom secureRandom = new SecureRandom();

			DTLSClientProtocol clientProtocol = new DTLSClientProtocol(secureRandom);
			DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

			MockDatagramAssociation network = new MockDatagramAssociation(1500);

			ServerThread serverThread = new ServerThread(serverProtocol, network.getServer());
			serverThread.start();

			DatagramTransport clientTransport = network.getClient();

			clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

			clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

			MockDTLSClient client = new MockDTLSClient(null);

			DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

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

			serverThread.shutdown();
		}

		public class ServerThread : Thread
		{
			internal readonly DTLSServerProtocol serverProtocol;
			internal readonly DatagramTransport serverTransport;
			internal volatile bool isShutdown = false;

			public ServerThread(DTLSServerProtocol serverProtocol, DatagramTransport serverTransport)
			{
				this.serverProtocol = serverProtocol;
				this.serverTransport = serverTransport;
			}

			public virtual void run()
			{
				try
				{
					MockDTLSServer server = new MockDTLSServer();
					DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport);
					byte[] buf = new byte[dtlsServer.getReceiveLimit()];
					while (!isShutdown)
					{
						int length = dtlsServer.receive(buf, 0, buf.Length, 1000);
						if (length >= 0)
						{
							dtlsServer.send(buf, 0, length);
						}
					}
					dtlsServer.close();
				}
				catch (Exception e)
				{
					Console.WriteLine(e.ToString());
					Console.Write(e.StackTrace);
				}
			}

			public virtual void shutdown()
			{
				if (!isShutdown)
				{
					isShutdown = true;
					this.join();
				}
			}
		}
	}

}