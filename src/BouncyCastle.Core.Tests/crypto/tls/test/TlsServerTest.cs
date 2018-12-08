using System;

namespace org.bouncycastle.crypto.tls.test
{

	using Streams = org.bouncycastle.util.io.Streams;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	/// <summary>
	/// A simple test designed to conduct a TLS handshake with an external TLS client.
	/// <para>
	/// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
	/// this package (under 'src/test/resources') for help configuring an external TLS client.
	/// </para>
	/// </summary>
	public class TlsServerTest
	{
		private static readonly SecureRandom secureRandom = new SecureRandom();

		public static void Main(string[] args)
		{
			InetAddress address = InetAddress.getLocalHost();
			int port = 5556;

			ServerSocket ss = new ServerSocket(port, 16, address);
			try
			{
				while (true)
				{
					Socket s = ss.accept();
					JavaSystem.@out.println("--------------------------------------------------------------------------------");
					JavaSystem.@out.println("Accepted " + s);
					ServerThread t = new ServerThread(s);
					t.start();
				}
			}
			finally
			{
				ss.close();
			}
		}

		public class ServerThread : Thread
		{
			internal readonly Socket s;

			public ServerThread(Socket s)
			{
				this.s = s;
			}

			public virtual void run()
			{
				try
				{
					MockTlsServer server = new MockTlsServer();
					TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
					serverProtocol.accept(server);
					OutputStream log = new TeeOutputStream(serverProtocol.getOutputStream(), System.out);
					Streams.pipeAll(serverProtocol.getInputStream(), log);
					serverProtocol.close();
				}
				catch (Exception e)
				{
					throw new RuntimeException(e);
				}
				finally
				{
					try
					{
						s.close();
					}
					catch (IOException)
					{
					}
					finally
					{
					}
				}
			}
		}
	}

}