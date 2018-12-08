namespace org.bouncycastle.est.jcajce
{





	/// <summary>
	/// Build an RFC7030 (EST) service based on the JSSE.
	/// </summary>
	public class JsseESTServiceBuilder : ESTServiceBuilder
	{
		protected internal SSLSocketFactoryCreator socketFactoryCreator;
		protected internal JsseHostnameAuthorizer hostNameAuthorizer = new JsseDefaultHostnameAuthorizer(null);
		protected internal int timeoutMillis = 0;
		protected internal ChannelBindingProvider bindingProvider;
		protected internal Set<string> supportedSuites = new HashSet<string>();
		protected internal long? absoluteLimit;
		protected internal SSLSocketFactoryCreatorBuilder sslSocketFactoryCreatorBuilder;
		protected internal bool filterCipherSuites = true;

		/// <summary>
		/// Create a builder for a client using a custom SSLSocketFactoryCreator.
		/// </summary>
		/// <param name="server">               name of the server to talk to (URL format). </param>
		/// <param name="socketFactoryCreator"> a custom creator of socket factories. </param>
		public JsseESTServiceBuilder(string server, SSLSocketFactoryCreator socketFactoryCreator) : base(server)
		{
			if (socketFactoryCreator == null)
			{
				throw new NullPointerException("No socket factory creator.");
			}
			this.socketFactoryCreator = socketFactoryCreator;

		}

		/// <summary>
		/// Create a builder for a client talking to a server that is not yet trusted.
		/// </summary>
		/// <param name="server"> name of the server to talk to (URL format). </param>
		public JsseESTServiceBuilder(string server) : base(server)
		{
			sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(JcaJceUtils.getTrustAllTrustManager());
		}

		/// <summary>
		/// Create a builder for a client talking to a trusted server.
		/// </summary>
		/// <param name="server">       name of the server to talk to (URL format). </param>
		/// <param name="trustManager"> </param>
		public JsseESTServiceBuilder(string server, X509TrustManager trustManager) : base(server)
		{
			sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(trustManager);
		}

		/// <summary>
		/// Create a builder for a client talking to a trusted server.
		/// </summary>
		/// <param name="server">       name of the server to talk to (URL format). </param>
		/// <param name="trustManager"> </param>
		public JsseESTServiceBuilder(string server, X509TrustManager[] trustManager) : base(server)
		{
			sslSocketFactoryCreatorBuilder = new SSLSocketFactoryCreatorBuilder(trustManager);
		}

		public virtual JsseESTServiceBuilder withHostNameAuthorizer(JsseHostnameAuthorizer hostNameAuthorizer)
		{
			this.hostNameAuthorizer = hostNameAuthorizer;
			return this;
		}

		public override JsseESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
		{
			this.clientProvider = clientProvider;
			return this;
		}

		public virtual JsseESTServiceBuilder withTimeout(int timeoutMillis)
		{
			this.timeoutMillis = timeoutMillis;
			return this;
		}

		public virtual JsseESTServiceBuilder withReadLimit(long absoluteLimit)
		{
			this.absoluteLimit = absoluteLimit;
			return this;
		}


		public virtual JsseESTServiceBuilder withChannelBindingProvider(ChannelBindingProvider channelBindingProvider)
		{
			this.bindingProvider = channelBindingProvider;
			return this;
		}

		public virtual JsseESTServiceBuilder addCipherSuites(string name)
		{
			this.supportedSuites.add(name);
			return this;
		}

		public virtual JsseESTServiceBuilder addCipherSuites(string[] names)
		{
			this.supportedSuites.addAll(Arrays.asList(names));
			return this;
		}

		public virtual JsseESTServiceBuilder withTLSVersion(string tlsVersion)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}

			this.sslSocketFactoryCreatorBuilder.withTLSVersion(tlsVersion);


			return this;
		}

		public virtual JsseESTServiceBuilder withSecureRandom(SecureRandom secureRandom)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}

			this.sslSocketFactoryCreatorBuilder.withSecureRandom(secureRandom);


			return this;
		}

		/// <summary>
		/// Configure this builder to use the provider with the passed in name.
		/// </summary>
		/// <param name="tlsProviderName"> the name JSSE Provider to use. </param>
		/// <returns> the current builder instance. </returns>
		/// <exception cref="NoSuchProviderException"> if the specified provider does not exist. </exception>
		public virtual JsseESTServiceBuilder withProvider(string tlsProviderName)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}

			this.sslSocketFactoryCreatorBuilder.withProvider(tlsProviderName);

			return this;
		}

		/// <summary>
		/// Configure this builder to use the passed in provider.
		/// </summary>
		/// <param name="tlsProvider"> the JSSE Provider to use. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JsseESTServiceBuilder withProvider(Provider tlsProvider)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}

			this.sslSocketFactoryCreatorBuilder.withProvider(tlsProvider);
			return this;
		}

		public virtual JsseESTServiceBuilder withKeyManager(KeyManager keyManager)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}

			this.sslSocketFactoryCreatorBuilder.withKeyManager(keyManager);
			return this;
		}

		public virtual JsseESTServiceBuilder withKeyManagers(KeyManager[] keyManagers)
		{
			if (this.socketFactoryCreator != null)
			{
				throw new IllegalStateException("Socket Factory Creator was defined in the constructor.");
			}
			this.sslSocketFactoryCreatorBuilder.withKeyManagers(keyManagers);
			return this;
		}

		/// <summary>
		/// Filter cipher suites with supported before passing to JSSE provider.
		/// </summary>
		/// <param name="filter"> true, supplied cipher suites will be filtered with supported before passing to the JSSE provider. </param>
		/// <returns> this; </returns>
		public virtual JsseESTServiceBuilder withFilterCipherSuites(bool filter)
		{
			this.filterCipherSuites = filter;
			return this;
		}

		public override ESTService build()
		{
			if (bindingProvider == null)
			{
				bindingProvider = new ChannelBindingProviderAnonymousInnerClass(this);
			}

			if (socketFactoryCreator == null)
			{
				socketFactoryCreator = sslSocketFactoryCreatorBuilder.build();
			}


			if (clientProvider == null)
			{
				clientProvider = new DefaultESTHttpClientProvider(hostNameAuthorizer, socketFactoryCreator, timeoutMillis, bindingProvider, supportedSuites, absoluteLimit, filterCipherSuites);
			}

			return base.build();
		}

		public class ChannelBindingProviderAnonymousInnerClass : ChannelBindingProvider
		{
			private readonly JsseESTServiceBuilder outerInstance;

			public ChannelBindingProviderAnonymousInnerClass(JsseESTServiceBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public bool canAccessChannelBinding(Socket sock)
			{
				return false;
			}

			public byte[] getChannelBinding(Socket sock, string binding)
			{
				return null;
			}
		}

	}




}