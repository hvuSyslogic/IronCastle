using System;

namespace org.bouncycastle.cert.dane.fetcher
{



	/// <summary>
	/// A DANE entry fetcher implemented using JNDI.
	/// </summary>
	public class JndiDANEFetcherFactory : DANEEntryFetcherFactory
	{
		private const string DANE_TYPE = "53";

		private List dnsServerList = new ArrayList();
		private bool isAuthoritative;

		/// <summary>
		/// Specify the dnsServer to use.
		/// </summary>
		/// <param name="dnsServer"> IP address/name of the dns server </param>
		/// <returns> the current factory. </returns>
		public virtual JndiDANEFetcherFactory usingDNSServer(string dnsServer)
		{
			this.dnsServerList.add(dnsServer);

			return this;
		}

		/// <summary>
		/// Specify requests must be authoritative, or not (default false).
		/// </summary>
		/// <param name="isAuthoritative"> true if requests must be authoritative, false otherwise. </param>
		/// <returns> the current factory.. </returns>
		public virtual JndiDANEFetcherFactory setAuthoritative(bool isAuthoritative)
		{
			this.isAuthoritative = isAuthoritative;

			return this;
		}

		/// <summary>
		/// Build an entry fetcher for the specified domain name.
		/// </summary>
		/// <param name="domainName"> the domain name of interest. </param>
		/// <returns> a resolver for fetching entry's associated with domainName. </returns>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.cert.dane.DANEEntryFetcher build(final String domainName)
		public virtual DANEEntryFetcher build(string domainName)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.Hashtable env = new java.util.Hashtable();
			Hashtable env = new Hashtable();

			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
			env.put(Context.AUTHORITATIVE, isAuthoritative ? "true" : "false"); // JDK compatibility

			if (dnsServerList.size() > 0)
			{
				StringBuffer dnsServers = new StringBuffer();

				for (Iterator it = dnsServerList.iterator(); it.hasNext();)
				{
					if (dnsServers.length() > 0)
					{
						dnsServers.append(" ");
					}
					dnsServers.append("dns://" + it.next());
				}

				env.put(Context.PROVIDER_URL, dnsServers.ToString());
			}

			return new DANEEntryFetcherAnonymousInnerClass(this, domainName, env);
		}

		public class DANEEntryFetcherAnonymousInnerClass : DANEEntryFetcher
		{
			private readonly JndiDANEFetcherFactory outerInstance;

			private string domainName;
			private Hashtable env;

			public DANEEntryFetcherAnonymousInnerClass(JndiDANEFetcherFactory outerInstance, string domainName, Hashtable env)
			{
				this.outerInstance = outerInstance;
				this.domainName = domainName;
				this.env = env;
			}

			public List getEntries()
			{
				List entries = new ArrayList();

				try
				{
					DirContext ctx = new InitialDirContext(env);

					NamingEnumeration bindings;
					if (domainName.IndexOf("_smimecert.", StringComparison.Ordinal) > 0)
					{
						// need to use fully qualified domain name if using named DNS server.
						Attributes attrs = ctx.getAttributes(domainName, new string[]{DANE_TYPE});
						Attribute smimeAttr = attrs.get(DANE_TYPE);

						if (smimeAttr != null)
						{
							outerInstance.addEntries(entries, domainName, smimeAttr);
						}
					}
					else
					{
						bindings = ctx.listBindings("_smimecert." + domainName);

						while (bindings.hasMore())
						{
							Binding b = (Binding)bindings.next();

							DirContext sc = (DirContext)b.getObject();

							string name = sc.getNameInNamespace().substring(1, (sc.getNameInNamespace().length() - 1) - 1);

							// need to use fully qualified domain name if using named DNS server.
							Attributes attrs = ctx.getAttributes(name, new string[]{DANE_TYPE});
							Attribute smimeAttr = attrs.get(DANE_TYPE);

							if (smimeAttr != null)
							{
								string fullName = sc.getNameInNamespace();
								string domainName = fullName.Substring(1, (fullName.Length - 1) - 1);

								outerInstance.addEntries(entries, domainName, smimeAttr);
							}
						}
					}

					return entries;
				}
				catch (NamingException e)
				{
					throw new DANEException("Exception dealing with DNS: " + e.Message, e);
				}
			}
		}

		private void addEntries(List entries, string domainName, Attribute smimeAttr)
		{
			for (int index = 0; index != smimeAttr.size(); index++)
			{
				byte[] data = (byte[])smimeAttr.get(index);

				if (DANEEntry.isValidCertificate(data))
				{
					try
					{
						entries.add(new DANEEntry(domainName, data));
					}
					catch (IOException e)
					{
						throw new DANEException("Exception parsing entry: " + e.Message, e);
					}
				}
			}
		}
	}

}