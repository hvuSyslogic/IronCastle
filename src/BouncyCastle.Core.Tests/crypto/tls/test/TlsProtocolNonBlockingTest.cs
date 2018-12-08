namespace org.bouncycastle.crypto.tls.test
{

	using Arrays = org.bouncycastle.util.Arrays;

	using TestCase = junit.framework.TestCase;

	public class TlsProtocolNonBlockingTest : TestCase
	{
		public virtual void testClientServerFragmented()
		{
			// tests if it's really non-blocking when partial records arrive
			testClientServer(true);
		}

		public virtual void testClientServerNonFragmented()
		{
			testClientServer(false);
		}

		private static void testClientServer(bool fragment)
		{
			SecureRandom secureRandom = new SecureRandom();

			TlsClientProtocol clientProtocol = new TlsClientProtocol(secureRandom);
			TlsServerProtocol serverProtocol = new TlsServerProtocol(secureRandom);

			clientProtocol.connect(new MockTlsClient(null));
			serverProtocol.accept(new MockTlsServer());

			// pump handshake
			bool hadDataFromServer = true;
			bool hadDataFromClient = true;
			while (hadDataFromServer || hadDataFromClient)
			{
				hadDataFromServer = pumpData(serverProtocol, clientProtocol, fragment);
				hadDataFromClient = pumpData(clientProtocol, serverProtocol, fragment);
			}

			// send data in both directions
			byte[] data = new byte[1024];
			secureRandom.nextBytes(data);
			writeAndRead(clientProtocol, serverProtocol, data, fragment);
			writeAndRead(serverProtocol, clientProtocol, data, fragment);

			// close the connection
			clientProtocol.close();
			pumpData(clientProtocol, serverProtocol, fragment);
			serverProtocol.closeInput();
			checkClosed(serverProtocol);
			checkClosed(clientProtocol);
		}

		private static void writeAndRead(TlsProtocol writer, TlsProtocol reader, byte[] data, bool fragment)
		{
			int dataSize = data.Length;
			writer.offerOutput(data, 0, dataSize);
			pumpData(writer, reader, fragment);

			assertEquals(dataSize, reader.getAvailableInputBytes());
			byte[] readData = new byte[dataSize];
			reader.readInput(readData, 0, dataSize);
			assertArrayEquals(data, readData);
		}

		private static bool pumpData(TlsProtocol from, TlsProtocol to, bool fragment)
		{
			int byteCount = from.getAvailableOutputBytes();
			if (byteCount == 0)
			{
				return false;
			}

			if (fragment)
			{
				while (from.getAvailableOutputBytes() > 0)
				{
					byte[] buffer = new byte[1];
					from.readOutput(buffer, 0, 1);
					to.offerInput(buffer);
				}
			}
			else
			{
				byte[] buffer = new byte[byteCount];
				from.readOutput(buffer, 0, buffer.Length);
				to.offerInput(buffer);
			}

			return true;
		}

		private static void checkClosed(TlsProtocol protocol)
		{
			assertTrue(protocol.isClosed());

			try
			{
				protocol.offerInput(new byte[10]);
				fail("Input was accepted after close");
			}
			catch (IOException)
			{
			}

			try
			{
				protocol.offerOutput(new byte[10], 0, 10);
				fail("Output was accepted after close");
			}
			catch (IOException)
			{
			}
		}

		private static void assertArrayEquals(byte[] a, byte[] b)
		{
			assertTrue(Arrays.areEqual(a, b));
		}
	}

}