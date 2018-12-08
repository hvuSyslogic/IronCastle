namespace org.bouncycastle.x509
{
	using Selector = org.bouncycastle.util.Selector;

	public abstract class X509StoreSpi
	{
		public abstract void engineInit(X509StoreParameters parameters);

		public abstract Collection engineGetMatches(Selector selector);
	}

}