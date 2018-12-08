namespace org.bouncycastle.est.jcajce
{



	/// <summary>
	/// A basic builder to allow configuration of an SSLContext used to create an SSLSocketFactory.
	/// </summary>
	public class SSLSocketFactoryCreatorBuilder
	{
		protected internal string tlsVersion = "TLS";
		protected internal Provider tlsProvider;
		protected internal KeyManager[] keyManagers;
		protected internal X509TrustManager[] trustManagers;
		protected internal SecureRandom secureRandom = new SecureRandom();

		public SSLSocketFactoryCreatorBuilder(X509TrustManager trustManager)
		{
			if (trustManager == null)
			{
				throw new NullPointerException("Trust managers can not be null");
			}
			this.trustManagers = new X509TrustManager[]{trustManager};
		}

		public SSLSocketFactoryCreatorBuilder(X509TrustManager[] trustManagers)
		{
			if (trustManagers == null)
			{
				throw new NullPointerException("Trust managers can not be null");
			}
			this.trustManagers = trustManagers;
		}

		public virtual SSLSocketFactoryCreatorBuilder withTLSVersion(string tlsVersion)
		{
			this.tlsVersion = tlsVersion;
			return this;
		}

		public virtual SSLSocketFactoryCreatorBuilder withSecureRandom(SecureRandom secureRandom)
		{
			this.secureRandom = secureRandom;
			return this;
		}

		/// <summary>
		/// Configure this builder to use the provider with the passed in name.
		/// </summary>
		/// <param name="tlsProviderName"> the name JSSE Provider to use. </param>
		/// <returns> the current builder instance. </returns>
		/// <exception cref="NoSuchProviderException"> if the specified provider does not exist. </exception>
		public virtual SSLSocketFactoryCreatorBuilder withProvider(string tlsProviderName)
		{
			this.tlsProvider = Security.getProvider(tlsProviderName);
			if (this.tlsProvider == null)
			{
				throw new NoSuchProviderException("JSSE provider not found: " + tlsProviderName);
			}
			return this;
		}

		/// <summary>
		/// Configure this builder to use the passed in provider.
		/// </summary>
		/// <param name="tlsProvider"> the JSSE Provider to use. </param>
		/// <returns> the current builder instance. </returns>
		public virtual SSLSocketFactoryCreatorBuilder withProvider(Provider tlsProvider)
		{
			this.tlsProvider = tlsProvider;
			return this;
		}

		public virtual SSLSocketFactoryCreatorBuilder withKeyManager(KeyManager keyManager)
		{
			if (keyManager == null)
			{
				this.keyManagers = null;
			}
			else
			{
				this.keyManagers = new KeyManager[]{keyManager};
			}
			return this;
		}

		public virtual SSLSocketFactoryCreatorBuilder withKeyManagers(KeyManager[] keyManagers)
		{
			this.keyManagers = keyManagers;

			return this;
		}

		public virtual SSLSocketFactoryCreator build()
		{
			return new SSLSocketFactoryCreatorAnonymousInnerClass(this);
		}

		public class SSLSocketFactoryCreatorAnonymousInnerClass : SSLSocketFactoryCreator
		{
			private readonly SSLSocketFactoryCreatorBuilder outerInstance;

			public SSLSocketFactoryCreatorAnonymousInnerClass(SSLSocketFactoryCreatorBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public bool isTrusted()
			{
				for (int i = 0; i != outerInstance.trustManagers.Length; i++)
				{
					X509TrustManager tm = outerInstance.trustManagers[i];
					if (tm.getAcceptedIssuers().length > 0)
					{
						return true;
					}
				}

				return false;
			}

			public SSLSocketFactory createFactory()
			{
				SSLContext ctx;

				if (outerInstance.tlsProvider != null)
				{
					ctx = SSLContext.getInstance(outerInstance.tlsVersion, outerInstance.tlsProvider);
				}
				else
				{
					ctx = SSLContext.getInstance(outerInstance.tlsVersion);
				}

				ctx.init(outerInstance.keyManagers, outerInstance.trustManagers, outerInstance.secureRandom);

				return ctx.getSocketFactory();
			}
		}
	}

}