namespace org.bouncycastle.cert.dane
{
	/// <summary>
	/// Factories for DANEEntryFetcher objects should implement this.
	/// <para>
	/// Note: the fetcher should be able to manage both requests of the form
	/// <pre>
	///     fetcher.build("test.org");
	/// </pre>
	/// and
	/// <pre>
	///     91d23d115b68072e7a38afeb7e295bd6392a19f25f8328b4ecae4778._smimecert.test.org
	/// </pre>
	/// In the case of the later ideally just returning a list containing the single entry.
	/// </para>
	/// </summary>
	public interface DANEEntryFetcherFactory
	{
		/// <summary>
		/// Build an entry fetcher for the specified domain name.
		/// </summary>
		/// <param name="domainName"> the domain name of interest. </param>
		/// <returns> a resolver for fetching entry's associated with domainName. </returns>
		DANEEntryFetcher build(string domainName);
	}

}