﻿using System;

namespace org.bouncycastle.crypto.tls.test
{

	using TestCase = junit.framework.TestCase;

	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public class TlsProtocolTest : TestCase
	{
		public virtual void testClientServer()
		{
			SecureRandom secureRandom = new SecureRandom();

			PipedInputStream clientRead = new PipedInputStream();
			PipedInputStream serverRead = new PipedInputStream();
			PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
			PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

			TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
			TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

			ServerThread serverThread = new ServerThread(serverProtocol);
			serverThread.start();

			MockTlsClient client = new MockTlsClient(null);
			clientProtocol.connect(client);

			// NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
			int length = 1000;

			byte[] data = new byte[length];
			secureRandom.nextBytes(data);

			OutputStream output = clientProtocol.getOutputStream();
			output.write(data);

			byte[] echo = new byte[data.Length];
			int count = Streams.readFully(clientProtocol.getInputStream(), echo);

			assertEquals(count, data.Length);
			assertTrue(Arrays.areEqual(data, echo));

			output.close();

			serverThread.join();
		}

		public class ServerThread : Thread
		{
			internal readonly TlsServerProtocol serverProtocol;

			public ServerThread(TlsServerProtocol serverProtocol)
			{
				this.serverProtocol = serverProtocol;
			}

			public virtual void run()
			{
				try
				{
					MockTlsServer server = new MockTlsServer();
					serverProtocol.accept(server);
					Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
					serverProtocol.close();
				}
				catch (Exception)
				{
	//                throw new RuntimeException(e);
				}
			}
		}
	}

}