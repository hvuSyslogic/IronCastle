namespace org.bouncycastle.cert.dane
{
	/// <summary>
	/// Builder for the DANECertificateStore.
	/// </summary>
	public class DANEEntryStoreBuilder
	{
		private readonly DANEEntryFetcherFactory daneEntryFetcher;

		public DANEEntryStoreBuilder(DANEEntryFetcherFactory daneEntryFetcher)
		{
			this.daneEntryFetcher = daneEntryFetcher;
		}

		/// <summary>
		/// Build a DANECertificateStore from the provided domainName details.
		/// </summary>
		/// <param name="domainName"> the domain name to look up the _smimecert entries in. </param>
		/// <returns> a Store of DANEEntry representing the _smimecert entries containing certificates. </returns>
		/// <exception cref="DANEException"> in the case of a DNS issue or encoding issue with a DNS record. </exception>
		public virtual DANEEntryStore build(string domainName)
		{
			return new DANEEntryStore(daneEntryFetcher.build(domainName).getEntries());
		}
	}

}