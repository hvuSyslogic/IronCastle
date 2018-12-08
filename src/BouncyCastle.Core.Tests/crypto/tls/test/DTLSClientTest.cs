using System.Text;

namespace org.bouncycastle.crypto.tls.test
{


	/// <summary>
	/// A simple test designed to conduct a DTLS handshake with an external DTLS server.
	/// <para>
	/// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
	/// this package (under 'src/test/resources') for help configuring an external DTLS server.
	/// </para>
	/// </summary>
	public class DTLSClientTest
	{
		private static readonly SecureRandom secureRandom = new SecureRandom();

		public static void Main(string[] args)
		{
			InetAddress address = InetAddress.getLocalHost();
			int port = 5556;

			TlsSession session = createSession(address, port);

			MockDTLSClient client = new MockDTLSClient(session);

			DTLSTransport dtls = openDTLSConnection(address, port, client);

			JavaSystem.@out.println("Receive limit: " + dtls.getReceiveLimit());
			JavaSystem.@out.println("Send limit: " + dtls.getSendLimit());

			// Send and hopefully receive a packet back

			byte[] request = "Hello World!\n".GetBytes(Encoding.UTF8);
			dtls.send(request, 0, request.Length);

			byte[] response = new byte[dtls.getReceiveLimit()];
			int received = dtls.receive(response, 0, response.Length, 30000);
			if (received >= 0)
			{
				JavaSystem.@out.println(StringHelper.NewString(response, 0, received, "UTF-8"));
			}

			dtls.close();
		}

		private static TlsSession createSession(InetAddress address, int port)
		{
			MockDTLSClient client = new MockDTLSClient(null);
			DTLSTransport dtls = openDTLSConnection(address, port, client);
			TlsSession session = client.getSessionToResume();
			dtls.close();
			return session;
		}

		private static DTLSTransport openDTLSConnection(InetAddress address, int port, TlsClient client)
		{
			DatagramSocket socket = new DatagramSocket();
			socket.connect(address, port);

			int mtu = 1500;
			DatagramTransport transport = new UDPTransport(socket, mtu);
			transport = new UnreliableDatagramTransport(transport, secureRandom, 0, 0);
			transport = new LoggingDatagramTransport(transport, System.out);

			DTLSClientProtocol protocol = new DTLSClientProtocol(secureRandom);

			return protocol.connect(client, transport);
		}
	}

}