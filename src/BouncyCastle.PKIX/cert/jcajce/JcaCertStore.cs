namespace org.bouncycastle.cert.jcajce
{

	using CollectionStore = org.bouncycastle.util.CollectionStore;

	/// <summary>
	/// Class for storing Certificates for later lookup.
	/// <para>
	/// The class will convert X509Certificate objects into X509CertificateHolder objects.
	/// </para>
	/// </summary>
	public class JcaCertStore : CollectionStore
	{
		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="collection"> - initial contents for the store, this is copied. </param>
		public JcaCertStore(Collection collection) : base(convertCerts(collection))
		{
		}

		private static Collection convertCerts(Collection collection)
		{
			List list = new ArrayList(collection.size());

			for (Iterator it = collection.iterator(); it.hasNext();)
			{
				object o = it.next();

				if (o is X509Certificate)
				{
					X509Certificate cert = (X509Certificate)o;

					try
					{
						list.add(new X509CertificateHolder(cert.getEncoded()));
					}
					catch (IOException e)
					{
						throw new CertificateEncodingException("unable to read encoding: " + e.Message);
					}
				}
				else
				{
					list.add((X509CertificateHolder)o);
				}
			}

			return list;
		}
	}

}