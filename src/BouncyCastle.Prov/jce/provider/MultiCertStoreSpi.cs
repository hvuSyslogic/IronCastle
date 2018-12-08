namespace org.bouncycastle.jce.provider
{

	public class MultiCertStoreSpi : CertStoreSpi
	{
		private MultiCertStoreParameters @params;

		public MultiCertStoreSpi(CertStoreParameters @params) : base(@params)
		{

			if (!(@params is MultiCertStoreParameters))
			{
				throw new InvalidAlgorithmParameterException("org.bouncycastle.jce.provider.MultiCertStoreSpi: parameter must be a MultiCertStoreParameters object\n" + @params.ToString());
			}

			this.@params = (MultiCertStoreParameters)@params;
		}

		public virtual Collection engineGetCertificates(CertSelector certSelector)
		{
			bool searchAllStores = @params.getSearchAllStores();
			Iterator iter = @params.getCertStores().iterator();
			List allCerts = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;

			while (iter.hasNext())
			{
				CertStore store = (CertStore)iter.next();
				Collection certs = store.getCertificates(certSelector);

				if (searchAllStores)
				{
					allCerts.addAll(certs);
				}
				else if (!certs.isEmpty())
				{
					return certs;
				}
			}

			return allCerts;
		}

		public virtual Collection engineGetCRLs(CRLSelector crlSelector)
		{
			bool searchAllStores = @params.getSearchAllStores();
			Iterator iter = @params.getCertStores().iterator();
			List allCRLs = searchAllStores ? new ArrayList() : Collections.EMPTY_LIST;

			while (iter.hasNext())
			{
				CertStore store = (CertStore)iter.next();
				Collection crls = store.getCRLs(crlSelector);

				if (searchAllStores)
				{
					allCRLs.addAll(crls);
				}
				else if (!crls.isEmpty())
				{
					return crls;
				}
			}

			return allCRLs;
		}
	}

}