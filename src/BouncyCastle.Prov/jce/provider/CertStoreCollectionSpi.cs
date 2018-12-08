namespace org.bouncycastle.jce.provider
{

	public class CertStoreCollectionSpi : CertStoreSpi
	{
		private CollectionCertStoreParameters @params;

		public CertStoreCollectionSpi(CertStoreParameters @params) : base(@params)
		{

			if (!(@params is CollectionCertStoreParameters))
			{
				throw new InvalidAlgorithmParameterException("org.bouncycastle.jce.provider.CertStoreCollectionSpi: parameter must be a CollectionCertStoreParameters object\n" + @params.ToString());
			}

			this.@params = (CollectionCertStoreParameters)@params;
		}

		public virtual Collection engineGetCertificates(CertSelector selector)
		{
			List col = new ArrayList();
			Iterator iter = @params.getCollection().iterator();

			if (selector == null)
			{
				while (iter.hasNext())
				{
					object obj = iter.next();

					if (obj is Certificate)
					{
						col.add(obj);
					}
				}
			}
			else
			{
				while (iter.hasNext())
				{
					object obj = iter.next();

					if ((obj is Certificate) && selector.match((Certificate)obj))
					{
						col.add(obj);
					}
				}
			}

			return col;
		}


		public virtual Collection engineGetCRLs(CRLSelector selector)
		{
			List col = new ArrayList();
			Iterator iter = @params.getCollection().iterator();

			if (selector == null)
			{
				while (iter.hasNext())
				{
					object obj = iter.next();

					if (obj is CRL)
					{
						col.add(obj);
					}
				}
			}
			else
			{
				while (iter.hasNext())
				{
					object obj = iter.next();

					if ((obj is CRL) && selector.match((CRL)obj))
					{
						col.add(obj);
					}
				}
			}

			return col;
		}
	}

}