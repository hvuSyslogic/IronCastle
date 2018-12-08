using System;

namespace org.bouncycastle.est.jcajce
{


	using Properties = org.bouncycastle.util.Properties;

	public class DefaultESTClient : ESTClient
	{
		private static readonly Charset utf8 = Charset.forName("UTF-8");
		private static byte[] CRLF = new byte[]{(byte)'\r', (byte)'\n'};
		private readonly ESTClientSourceProvider sslSocketProvider;

		public DefaultESTClient(ESTClientSourceProvider sslSocketProvider)
		{
			this.sslSocketProvider = sslSocketProvider;
		}

		private static void writeLine(OutputStream os, string s)
		{
			os.write(s.GetBytes());
			os.write(CRLF);
		}

		public virtual ESTResponse doRequest(ESTRequest req)
		{
			ESTResponse resp = null;
			ESTRequest r = req;
			int rcCount = 15;
			do
			{
				resp = performRequest(r);
				r = redirectURL(resp);
			} while (r != null && --rcCount > 0); // Follow redirects.

			if (rcCount == 0)
			{
				throw new ESTException("Too many redirects..");
			}

			return resp;
		}

		public virtual ESTRequest redirectURL(ESTResponse response)
		{
			ESTRequest redirectingRequest = null;

			if (response.getStatusCode() >= 300 && response.getStatusCode() <= 399)
			{

				switch (response.getStatusCode())
				{
				case 301:
				case 302:
				case 303:
				case 306:
				case 307:
					string loc = response.getHeader("Location");
					if ("".Equals(loc))
					{
						throw new ESTException("Redirect status type: " + response.getStatusCode() + " but no location header");
					}

					ESTRequestBuilder requestBuilder = new ESTRequestBuilder(response.getOriginalRequest());
					if (loc.StartsWith("http", StringComparison.Ordinal))
					{
						redirectingRequest = requestBuilder.withURL(new URL(loc)).build();
					}
					else
					{
						URL u = response.getOriginalRequest().getURL();
						redirectingRequest = requestBuilder.withURL(new URL(u.getProtocol(), u.getHost(), u.getPort(), loc)).build();
					}
					break;
				default:
					throw new ESTException("Client does not handle http status code: " + response.getStatusCode());
				}
			}

			if (redirectingRequest != null)
			{
				response.close(); // Close original request.
			}

			return redirectingRequest;
		}

		public virtual ESTResponse performRequest(ESTRequest c)
		{


			ESTResponse res = null;
			Source socketSource = null;
			try
			{
				socketSource = sslSocketProvider.makeSource(c.getURL().getHost(), c.getURL().getPort());
				if (c.getListener() != null)
				{
					c = c.getListener().onConnection(socketSource, c);
				}

				//  socketSource = new SSLSocketSource((SSLSocket)sock);

				OutputStream os = null;

				Set<string> opts = Properties.asKeySet("org.bouncycastle.debug.est");
				if (opts.contains("output") || opts.contains("all"))
				{
					os = new PrintingOutputStream(this, socketSource.getOutputStream());
				}
				else
				{
					os = socketSource.getOutputStream();
				}

				string req = c.getURL().getPath() + ((c.getURL().getQuery() != null) ? c.getURL().getQuery() : "");

				ESTRequestBuilder rb = new ESTRequestBuilder(c);

				Map<string, String[]> headers = c.getHeaders();

				if (!headers.containsKey("Connection"))
				{
					rb.addHeader("Connection", "close");
				}

				// Replace host header.
				URL u = c.getURL();
				if (u.getPort() > -1)
				{
					rb.setHeader("Host", string.Format("{0}:{1:D}", u.getHost(), u.getPort()));
				}
				else
				{
					rb.setHeader("Host", u.getHost());
				}


				ESTRequest rc = rb.build();

				writeLine(os, rc.getMethod() + " " + req + " HTTP/1.1");


				for (Iterator it = rc.getHeaders().entrySet().iterator(); it.hasNext();)
				{
					Map.Entry<string, String[]> ent = (Map.Entry<string, String[]>)it.next();
					string[] vs = (string[])ent.getValue();

					for (int i = 0; i != vs.Length; i++)
					{
						writeLine(os, ent.getKey() + ": " + vs[i]);
					}
				}

				os.write(CRLF);
				os.flush();

				rc.writeData(os);

				os.flush();

				if (rc.getHijacker() != null)
				{
					res = rc.getHijacker().hijack(rc, socketSource);
					return res;
				}
				else
				{
					res = new ESTResponse(rc, socketSource);
				}

				return res;

			}
			finally
			{
				// Close only if response not generated.
				if (socketSource != null && res == null)
				{
					socketSource.close();
				}
			}

		}

		public class PrintingOutputStream : OutputStream
		{
			private readonly DefaultESTClient outerInstance;

			internal readonly OutputStream tgt;

			public PrintingOutputStream(DefaultESTClient outerInstance, OutputStream tgt)
			{
				this.outerInstance = outerInstance;
				this.tgt = tgt;
			}

			public virtual void write(int b)
			{
				JavaSystem.@out.print(((char)b).ToString());
				tgt.write(b);
			}
		}
	}

}