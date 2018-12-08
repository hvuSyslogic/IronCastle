using System;

namespace org.bouncycastle.est.jcajce
{



	using Strings = org.bouncycastle.util.Strings;

	public class DefaultESTClientSourceProvider : ESTClientSourceProvider
	{

		private readonly SSLSocketFactory sslSocketFactory;
		private readonly JsseHostnameAuthorizer hostNameAuthorizer;
		private readonly int timeout;
		private readonly ChannelBindingProvider bindingProvider;
		private readonly Set<string> cipherSuites;
		private readonly long? absoluteLimit;
		private readonly bool filterSupportedSuites;


		public DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, JsseHostnameAuthorizer hostNameAuthorizer, int timeout, ChannelBindingProvider bindingProvider, Set<string> cipherSuites, long? absoluteLimit, bool filterSupportedSuites)
		{
			this.sslSocketFactory = socketFactory;
			this.hostNameAuthorizer = hostNameAuthorizer;
			this.timeout = timeout;
			this.bindingProvider = bindingProvider;
			this.cipherSuites = cipherSuites;
			this.absoluteLimit = absoluteLimit;
			this.filterSupportedSuites = filterSupportedSuites;
		}


		public virtual Source makeSource(string host, int port)
		{
			SSLSocket sock = (SSLSocket)sslSocketFactory.createSocket(host, port);
			sock.setSoTimeout(timeout);

			if (cipherSuites != null && !cipherSuites.isEmpty())
			{
				// Filter supplied list with what is actually supported.
				if (filterSupportedSuites)
				{
					HashSet<string> fs = new HashSet<string>();
					string[] supportedCipherSuites = sock.getSupportedCipherSuites();
					for (int i = 0; i != supportedCipherSuites.Length; i++)
					{
						fs.add(supportedCipherSuites[i]);
					}

					List<string> j = new ArrayList<string>();
					for (Iterator it = cipherSuites.iterator(); it.hasNext();)
					{
						string s = (string)it.next();
						if (fs.contains(s))
						{
							j.add(s);
						}
					}

					if (j.isEmpty())
					{
						throw new IllegalStateException("No supplied cipher suite is supported by the provider.");
					}

					sock.setEnabledCipherSuites(j.toArray(new string[j.size()]));
				}
				else
				{
					sock.setEnabledCipherSuites(cipherSuites.toArray(new string[cipherSuites.size()]));
				}
			}


			sock.startHandshake();

			if (hostNameAuthorizer != null)
			{
				if (!hostNameAuthorizer.verified(host, sock.getSession()))
				{
					throw new IOException("Host name could not be verified.");
				}
			}

			{
				string t = Strings.toLowerCase(sock.getSession().getCipherSuite());
				if (t.Contains("_des_") || t.Contains("_des40_") || t.Contains("_3des_"))
				{
					throw new IOException("EST clients must not use DES ciphers");
				}
			}

			// check for use of null cipher and fail.
			if (Strings.toLowerCase(sock.getSession().getCipherSuite()).Contains("null"))
			{
				throw new IOException("EST clients must not use NULL ciphers");
			}

			// check for use of anon cipher and fail.
			if (Strings.toLowerCase(sock.getSession().getCipherSuite()).Contains("anon"))
			{
				throw new IOException("EST clients must not use anon ciphers");
			}

			// check for use of export cipher.
			if (Strings.toLowerCase(sock.getSession().getCipherSuite()).Contains("export"))
			{
				throw new IOException("EST clients must not use export ciphers");
			}

			if (sock.getSession().getProtocol().equalsIgnoreCase("tlsv1"))
			{
				try
				{
					sock.close();
				}
				catch (Exception)
				{
					// Deliberately ignored.
				}
				throw new IOException("EST clients must not use TLSv1");
			}


			if (hostNameAuthorizer != null && !hostNameAuthorizer.verified(host, sock.getSession()))
			{
				throw new IOException("Hostname was not verified: " + host);
			}
			return new LimitedSSLSocketSource(sock, bindingProvider, absoluteLimit);
		}
	}

}