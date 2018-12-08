namespace org.bouncycastle.jce.provider
{

	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Selector = org.bouncycastle.util.Selector;
	using X509CollectionStoreParameters = org.bouncycastle.x509.X509CollectionStoreParameters;
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;
	using X509StoreSpi = org.bouncycastle.x509.X509StoreSpi;

	public class X509StoreCertCollection : X509StoreSpi
	{
		private CollectionStore _store;

		public X509StoreCertCollection()
		{
		}

		public override void engineInit(X509StoreParameters @params)
		{
			if (!(@params is X509CollectionStoreParameters))
			{
				throw new IllegalArgumentException(@params.ToString());
			}

			_store = new CollectionStore(((X509CollectionStoreParameters)@params).getCollection());
		}

		public override Collection engineGetMatches(Selector selector)
		{
			return _store.getMatches(selector);
		}
	}

}