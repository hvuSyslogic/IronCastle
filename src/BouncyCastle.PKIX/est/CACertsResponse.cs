namespace org.bouncycastle.est
{
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// Holder class for a SimplePKIResponse containing the details making up /cacerts response.
	/// </summary>
	public class CACertsResponse
	{
		private readonly Store<X509CertificateHolder> store;
		private Store<X509CRLHolder> crlHolderStore;
		private readonly ESTRequest requestToRetry;
		private readonly Source session;
		private readonly bool trusted;

		public CACertsResponse(Store<X509CertificateHolder> store, Store<X509CRLHolder> crlHolderStore, ESTRequest requestToRetry, Source session, bool trusted)
		{
			this.store = store;
			this.requestToRetry = requestToRetry;
			this.session = session;
			this.trusted = trusted;
			this.crlHolderStore = crlHolderStore;
		}

		public virtual bool hasCertificates()
		{
			return store != null;
		}

		public virtual Store<X509CertificateHolder> getCertificateStore()
		{
			if (store == null)
			{
				throw new IllegalStateException("Response has no certificates.");
			}
			return store;
		}


		public virtual bool hasCRLs()
		{
			return crlHolderStore != null;
		}

		public virtual Store<X509CRLHolder> getCrlStore()
		{
			if (crlHolderStore == null)
			{
				throw new IllegalStateException("Response has no CRLs.");
			}
			return crlHolderStore;
		}


		public virtual ESTRequest getRequestToRetry()
		{
			return requestToRetry;
		}

		public virtual object getSession()
		{
			return session.getSession();
		}

		public virtual bool isTrusted()
		{
			return trusted;
		}
	}

}