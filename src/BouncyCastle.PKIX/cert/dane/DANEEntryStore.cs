namespace org.bouncycastle.cert.dane
{

	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;

	/// <summary>
	/// Class storing DANEEntry objects.
	/// </summary>
	public class DANEEntryStore : Store
	{
		private readonly Map entries;

		public DANEEntryStore(List entries)
		{
			Map entryMap = new HashMap();

			 for (Iterator it = entries.iterator(); it.hasNext();)
			 {
				 DANEEntry entry = (DANEEntry)it.next();

				 entryMap.put(entry.getDomainName(), entry);
			 }

			this.entries = Collections.unmodifiableMap(entryMap);
		}

		/// <summary>
		/// Return a collection of entries matching the passed in selector.
		/// </summary>
		/// <param name="selector"> the selector to validate entries against. </param>
		/// <returns> a possibly empty collection of matched entries. </returns>
		/// <exception cref="StoreException"> in case of an underlying issue. </exception>
		public virtual Collection getMatches(Selector selector)
		{
			if (selector == null)
			{
				return entries.values();
			}

			List results = new ArrayList();

			for (Iterator it = entries.values().iterator(); it.hasNext();)
			{
				object next = it.next();
				if (selector.match(next))
				{
					results.add(next);
				}
			}

			return Collections.unmodifiableList(results);
		}

		/// <summary>
		/// Return a Store of X509CertificateHolder objects representing all the certificates associated with
		/// entries in the store.
		/// </summary>
		/// <returns> a Store of X509CertificateHolder. </returns>
		public virtual Store toCertificateStore()
		{
			Collection col = this.getMatches(null);
			List certColl = new ArrayList(col.size());

			for (Iterator it = col.iterator(); it.hasNext();)
			{
				DANEEntry entry = (DANEEntry)it.next();

				certColl.add(entry.getCertificate());
			}

			return new CollectionStore(certColl);
		}
	}

}