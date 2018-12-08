using System.Text;

namespace org.bouncycastle.crypto.tls.test
{


	/// <summary>
	/// A simple test designed to conduct a TLS handshake with an external TLS server.
	/// <para>
	/// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
	/// this package (under 'src/test/resources') for help configuring an external TLS server.
	/// </para>
	/// </summary>
	public class TlsClientTest
	{
		private static readonly SecureRandom secureRandom = new SecureRandom();

		public static void Main(string[] args)
		{
			InetAddress address = InetAddress.getLocalHost();
			int port = 5556;

			long time1 = System.currentTimeMillis();

			MockTlsClient client = new MockTlsClient(null);
			TlsClientProtocol protocol = openTlsConnection(address, port, client);
			protocol.close();

			long time2 = System.currentTimeMillis();
			JavaSystem.@out.println("Elapsed 1: " + (time2 - time1) + "ms");

			client = new MockTlsClient(client.getSessionToResume());
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