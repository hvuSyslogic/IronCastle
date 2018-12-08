namespace org.bouncycastle.cert.dane
{

	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// A single shot fetcher for a certificate which will only request the specific DNS record if the
	/// DANEEntryFetcher used on construction supports it.
	/// </summary>
	public class DANECertificateFetcher
	{
		private readonly DANEEntryFetcherFactory fetcherFactory;
		private readonly DANEEntrySelectorFactory selectorFactory;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="fetcherFactory"> the fetcher to use for resolving requests. </param>
		/// <param name="digestCalculator"> the digest calculator to use for calculating sub-domains. </param>
		public DANECertificateFetcher(DANEEntryFetcherFactory fetcherFactory, DigestCalculator digestCalculator)
		{
			this.fetcherFactory = fetcherFactory;
			this.selectorFactory = new DANEEntrySelectorFactory(digestCalculator);
		}

		/// <summary>
		/// Fetch the certificates associated with the passed in email address if any exists.
		/// </summary>
		/// <param name="emailAddress"> the email address of interest. </param>
		/// <returns> a list of X509CertificateHolder objects, or an empty list if none present. </returns>
		/// <exception cref="DANEException"> in case of an underlying DNS or record parsing problem. </exception>
		public virtual List fetch(string emailAddress)
		{
			DANEEntrySelector daneSelector = selectorFactory.createSelector(emailAddress);

			List matches = fetcherFactory.build(daneSelector.getDomainName()).getEntries();
			List certs = new ArrayList(matches.size());

			for (Iterator it = matches.iterator(); it.hasNext();)
			{
				DANEEntry next = (DANEEntry)it.next();
				if (daneSelector.match(next))
				{
					certs.add(next.getCertificate());
				}
			}

			return Collections.unmodifiableList(certs);
		}
	}

}