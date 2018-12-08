namespace org.bouncycastle.x509
{

	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;

	/// @deprecated use CollectionStore - this class will be removed. 
	public class X509Store : Store
	{
		public static X509Store getInstance(string type, X509StoreParameters parameters)
		{
			try
			{
				X509Util.Implementation impl = X509Util.getImplementation("X509Store", type);

				return createStore(impl, parameters);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new NoSuchStoreException(e.Message);
			}
		}

		public static X509Store getInstance(string type, X509StoreParameters parameters, string provider)
		{
			return getInstance(type, parameters, X509Util.getProvider(provider));
		}

		public static X509Store getInstance(string type, X509StoreParameters parameters, Provider provider)
		{
			try
			{
				X509Util.Implementation impl = X509Util.getImplementation("X509Store", type, provider);

				return createStore(impl, parameters);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new NoSuchStoreException(e.Message);
			}
		}

		private static X509Store createStore(X509Util.Implementation impl, X509StoreParameters parameters)
		{
			X509StoreSpi spi = (X509StoreSpi)impl.getEngine();

			spi.engineInit(parameters);

			return new X509Store(impl.getProvider(), spi);
		}

		private Provider _provider;
		private X509StoreSpi _spi;

		private X509Store(Provider provider, X509StoreSpi spi)
		{
			_provider = provider;
			_spi = spi;
		}

		public virtual Provider getProvider()
		{
		   return _provider;
		}

		public virtual Collection getMatches(Selector selector)
		{
			return _spi.engineGetMatches(selector);
		}
	}

}