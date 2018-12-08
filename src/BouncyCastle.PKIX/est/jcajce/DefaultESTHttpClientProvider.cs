using System;

namespace org.bouncycastle.est.jcajce
{


	public class DefaultESTHttpClientProvider : ESTClientProvider
	{

		private readonly JsseHostnameAuthorizer hostNameAuthorizer;
		private readonly SSLSocketFactoryCreator socketFactoryCreator;

		private readonly int timeout;
		private readonly ChannelBindingProvider bindingProvider;
		private readonly Set<string> cipherSuites;
		private readonly long? absoluteLimit;
		private readonly bool filterCipherSuites;


		public DefaultESTHttpClientProvider(JsseHostnameAuthorizer hostNameAuthorizer, SSLSocketFactoryCreator socketFactoryCreator, int timeout, ChannelBindingProvider bindingProvider, Set<string> cipherSuites, long? absoluteLimit, bool filterCipherSuites)
		{

			this.hostNameAuthorizer = hostNameAuthorizer;
			this.socketFactoryCreator = socketFactoryCreator;
			this.timeout = timeout;
			this.bindingProvider = bindingProvider;
			this.cipherSuites = cipherSuites;
			this.absoluteLimit = absoluteLimit;
			this.filterCipherSuites = filterCipherSuites;
		}

		public virtual ESTClient makeClient()
		{
			try
			{
				SSLSocketFactory socketFactory = socketFactoryCreator.createFactory();
				return new DefaultESTClient(new DefaultESTClientSourceProvider(socketFactory, hostNameAuthorizer, timeout, bindingProvider, cipherSuites, absoluteLimit, filterCipherSuites));
			}
			catch (Exception e)
			{
				throw new ESTException(e.Message, e.InnerException);
			}
		}


		public virtual bool isTrusted()
		{
			return socketFactoryCreator.isTrusted();
		}
	}

}