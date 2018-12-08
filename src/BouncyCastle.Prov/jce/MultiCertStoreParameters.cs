namespace org.bouncycastle.jce
{

	public class MultiCertStoreParameters : CertStoreParameters
	{
		private Collection certStores;
		private bool searchAllStores;

		/// <summary>
		/// Create a parameters object which specifies searching of all the passed in stores.
		/// </summary>
		/// <param name="certStores"> CertStores making up the multi CertStore </param>
		public MultiCertStoreParameters(Collection certStores) : this(certStores, true)
		{
		}

		/// <summary>
		/// Create a parameters object which can be to used to make a multi store made up
		/// of the passed in CertStores. If the searchAllStores parameter is false, any search on
		/// the multi-store will terminate as soon as a search query produces a result.
		/// </summary>
		/// <param name="certStores"> CertStores making up the multi CertStore </param>
		/// <param name="searchAllStores"> true if all CertStores should be searched on request, false if a result
		/// should be returned on the first successful CertStore query. </param>
		public MultiCertStoreParameters(Collection certStores, bool searchAllStores)
		{
			this.certStores = certStores;
			this.searchAllStores = searchAllStores;
		}

		public virtual Collection getCertStores()
		{
			return certStores;
		}

		public virtual bool getSearchAllStores()
		{
			return searchAllStores;
		}

		public virtual object clone()
		{
			return this;
		}
	}

}