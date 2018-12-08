namespace org.bouncycastle.crypto.tls.test
{


	/// <summary>
	/// A simple test designed to conduct a DTLS handshake with an external DTLS client.
	/// <para>
	/// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
	/// this package (under 'src/test/resources') for help configuring an external DTLS client.
	/// </para>
	/// </summary>
	public class DTLSServerTest
	{
		public static void Main(string[] args)
		{
			int port = 5556;

			int mtu = 1500;

			SecureRandom secureRandom = new SecureRandom();

			DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

			byte[] data = new byte[mtu];
			DatagramPacket packet = new DatagramPacket(data, mtu);

			DatagramSocket socket = new DatagramSocket(port);
			socket.receive(packet);

			JavaSystem.@out.println("Accepting connection from " + packet.getAddress().getHostAddress() + ":" + port);
			socket.connect(packet.getAddress(), packet.getPort());

			/*
			 * NOTE: For simplicity, and since we don't yet have HelloVerifyRequest support, we just
			 * discard the initial packet, which the client should re-send anyway.
			 */

			DatagramTransport transport = new UDPTransport(socket, mtu);

			// Uncomment to see packets
	//        transport = new LoggingDatagramTransport(transport, System.out);

			MockDTLSServer server = new MockDTLSServer();
			DTLSTransport dtlsServer = serverProtocol.accept(server, transport);

			byte[] buf = new byte[dtlsServer.getReceiveLimit()];

			while (!socket.isClosed())
			{
				try
				{
					int length = dtlsServer.receive(buf, 0, buf.Length, 60000);
					if (length >= 0)
					{
						JavaSystem.@out.write(buf, 0, length);
						dtlsServer.send(buf, 0, length);
					}
				}
				catch (SocketTimeoutException)
				{
				}
			}

			dtlsServer.close();
		}
	}

}