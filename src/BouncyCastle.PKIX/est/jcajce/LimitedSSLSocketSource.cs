namespace org.bouncycastle.est.jcajce
{




	public class LimitedSSLSocketSource : Source<SSLSession>, TLSUniqueProvider, LimitedSource
	{
		protected internal readonly SSLSocket socket;
		private readonly ChannelBindingProvider bindingProvider;
		private readonly long? absoluteReadLimit;

		public LimitedSSLSocketSource(SSLSocket sock, ChannelBindingProvider bindingProvider, long? absoluteReadLimit)
		{
			this.socket = sock;
			this.bindingProvider = bindingProvider;
			this.absoluteReadLimit = absoluteReadLimit;
		}

		public virtual InputStream getInputStream()
		{
			return socket.getInputStream();
		}

		public virtual OutputStream getOutputStream()
		{
			return socket.getOutputStream();
		}

		public virtual SSLSession getSession()
		{
			return socket.getSession();
		}

		public virtual byte[] getTLSUnique()
		{
			if (isTLSUniqueAvailable())
			{
				return bindingProvider.getChannelBinding(socket, "tls-unique");
			}
			throw new IllegalStateException("No binding provider.");
		}

		public virtual bool isTLSUniqueAvailable()
		{
			return bindingProvider.canAccessChannelBinding(socket);
		}

		public virtual void close()
		{
			socket.close();
		}

		public virtual long? getAbsoluteReadLimit()
		{
			return absoluteReadLimit;
		}
	}

}