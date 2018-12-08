namespace org.bouncycastle.cert.jcajce
{

	using CollectionStore = org.bouncycastle.util.CollectionStore;

	/// <summary>
	/// Class for storing CRLs for later lookup.
	/// <para>
	/// The class will convert X509CRL objects into X509CRLHolder objects.
	/// </para>
	/// </summary>
	public class JcaCRLStore : CollectionStore
	{
		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="collection"> - initial contents for the store, this is copied. </param>
		public JcaCRLStore(Collection collection) : base(convertCRLs(collection))
		{
		}

		private static Collection convertCRLs(Collection collection)
		{
			List list = new ArrayList(collection.size());

			for (Iterator it = collection.iterator(); it.hasNext();)
			{
				object crl = it.next();

				if (crl is X509CRL)
				{
					try
					{
						list.add(new X509CRLHolder(((X509CRL)crl).getEncoded()));
					}
					catch (IOException e)
					{
						throw new CRLException("cannot read encoding: " + e.Message);

					}
				}
				else
				{
					list.add((X509CRLHolder)crl);
				}
			}

			return list;
		}
	}

}