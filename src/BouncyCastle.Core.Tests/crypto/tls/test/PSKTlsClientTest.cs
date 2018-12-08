using System.Text;

namespace org.bouncycastle.crypto.tls.test
{


	/// <summary>
	/// A simple test designed to conduct a TLS handshake with an external TLS server.
	/// <para>
	/// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
	/// this package (under 'src/test/resources') for help configuring an external TLS server.
	/// </para>
	/// </para><para>
	/// In both cases, extra options are required to enable PSK ciphersuites and configure identities/keys.
	/// </p>
	/// </summary>
	public class PSKTlsClientTest
	{
		private static readonly SecureRandom secureRandom = new SecureRandom();

		public static void Main(string[] args)
		{
			InetAddress address = InetAddress.getLocalHost();
			int port = 5556;

			long time1 = System.currentTimeMillis();

			/*
			 * Note: This is the default PSK identity for 'openssl s_server' testing, the server must be
			 * started with "-psk 6161616161" to make the keys match, and possibly the "-psk_hint"
			 * option should be present.
			 */
			string psk_identity = "Client_identity";
			byte[] psk = new byte[]{0x61, 0x61, 0x61, 0x61, 0x61};

			BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(psk_identity, psk);

			MockPSKTlsClient client = new MockPSKTlsClient(null, pskIdentity);
			TlsClientProtocol protocol = openTlsConnection(address, port, client);
			protocol.close();

			long time2 = System.currentTimeMillis();
			JavaSystem.@out.println("Elapsed 1: " + (time2 - time1) + "ms");

			client = new MockPSKTlsClient(client.getSessionToResume(), pskIdentity);
			protocol = openTlsConnection(address, port, client);

			long time3 = System.currentTimeMillis();
			JavaSystem.@out.println("Elapsed 2: " + (time3 - time2) + "ms");

			OutputStream output = protocol.getOutputStream();
			output.write("GET / HTTP/1.1\r\n\r\n".GetBytes(Encoding.UTF8));
			output.flush();

			InputStream input = protocol.getInputStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(input));

			string line;
			while (!string.ReferenceEquals((line = reader.readLine()), null))
			{
				JavaSystem.@out.println(">>> " + line);
			}

			protocol.close();
		}

		internal static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client)
		{
			Socket s = new Socket(address, port);
			TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
			protocol.connect(client);
			return protocol;
		}
	}

}