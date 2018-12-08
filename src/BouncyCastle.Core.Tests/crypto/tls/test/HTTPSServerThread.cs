using System;

namespace org.bouncycastle.crypto.tls.test
{


	public class HTTPSServerThread : Thread
	{
		private const int PORT_NO = 8003;
		private static readonly char[] SERVER_PASSWORD = "serverPassword".ToCharArray();
		private static readonly char[] TRUST_STORE_PASSWORD = "trustPassword".ToCharArray();

		/// <summary>
		/// Read a HTTP request
		/// </summary>
		private void readRequest(InputStream @in)
		{
			int ch = 0;
			int lastCh = 0;
			while ((ch = @in.read()) >= 0 && (ch != '\n' && lastCh != '\n'))
			{
				if (ch != '\r')
				{
					lastCh = ch;
				}
			}
		}

		/// <summary>
		/// Send a response
		/// </summary>
		private void sendResponse(OutputStream @out)
		{
			PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(@out));
			pWrt.print("HTTP/1.1 200 OK\r\n");
			pWrt.print("Content-Type: text/html\r\n");
			pWrt.print("\r\n");
			pWrt.print("<html>\r\n");
			pWrt.print("<body>\r\n");
			pWrt.print("Hello World!\r\n");
			pWrt.print("</body>\r\n");
			pWrt.print("</html>\r\n");
			pWrt.flush();
		}

		public virtual SSLContext createSSLContext()
		{
			KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
			KeyStore serverStore = KeyStore.getInstance("JKS");

			serverStore.load(new ByteArrayInputStream(KeyStores.server), SERVER_PASSWORD);

			mgrFact.init(serverStore, SERVER_PASSWORD);

			// set up a trust manager so we can recognize the server
			TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
			KeyStore trustStore = KeyStore.getInstance("JKS");

			trustStore.load(new ByteArrayInputStream(KeyStores.trustStore), TRUST_STORE_PASSWORD);

			trustFact.init(trustStore);

			// create a context and set up a socket factory
			SSLContext sslContext = SSLContext.getInstance("TLS");

			sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

			return sslContext;
		}

		public virtual void run()
		{
			try
			{
				SSLContext sslContext = createSSLContext();
				SSLServerSocketFactory fact = sslContext.getServerSocketFactory();

				SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);
				SSLSocket sslSock = (SSLSocket)sSock.accept();

				sslSock.startHandshake();

				readRequest(sslSock.getInputStream());

				SSLSession session = sslSock.getSession();

				sendResponse(sslSock.getOutputStream());

				sslSock.close();
				sSock.close();
			}
			catch (Exception e)
			{
				throw new RuntimeException(e);
			}
		}
	}

}