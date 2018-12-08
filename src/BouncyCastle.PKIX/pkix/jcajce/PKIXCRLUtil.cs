using System;

namespace org.bouncycastle.pkix.jcajce
{

	using PKIXCRLStoreSelector = org.bouncycastle.jcajce.PKIXCRLStoreSelector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;

	public class PKIXCRLUtil
	{
		public virtual Set findCRLs(PKIXCRLStoreSelector crlselect, DateTime validityDate, List certStores, List pkixCrlStores)
		{
			Set initialSet = new HashSet();

			// get complete CRL(s)
			try
			{
				initialSet.addAll(findCRLs(crlselect, pkixCrlStores));
				initialSet.addAll(findCRLs(crlselect, certStores));
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Exception obtaining complete CRLs.", e);
			}

			Set finalSet = new HashSet();

			// based on RFC 5280 6.3.3
			for (Iterator it = initialSet.iterator(); it.hasNext();)
			{
				X509CRL crl = (X509CRL)it.next();

				if (crl.getNextUpdate().after(validityDate))
				{
					X509Certificate cert = crlselect.getCertificateChecking();

					if (cert != null)
					{
						if (crl.getThisUpdate().before(cert.getNotAfter()))
						{
							finalSet.add(crl);
						}
					}
					else
					{
						finalSet.add(crl);
					}
				}
			}

			return finalSet;
		}

		/// <summary>
		/// Return a Collection of all CRLs found in the X509Store's that are
		/// matching the crlSelect criteriums.
		/// </summary>
		/// <param name="crlSelect"> a <seealso cref="PKIXCRLStoreSelector"/> object that will be used
		///            to select the CRLs </param>
		/// <param name="crlStores"> a List containing only
		///            <seealso cref="Store"/> objects.
		///            These are used to search for CRLs
		/// </param>
		/// <returns> a Collection of all found <seealso cref="X509CRL X509CRL"/> objects. May be
		///         empty but never <code>null</code>. </returns>
		private Collection findCRLs(PKIXCRLStoreSelector crlSelect, List crlStores)
		{
			Set crls = new HashSet();
			Iterator iter = crlStores.iterator();

			AnnotatedException lastException = null;
			bool foundValidStore = false;

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is Store)
				{
					Store store = (Store)obj;

					try
					{
						crls.addAll(store.getMatches(crlSelect));
						foundValidStore = true;
					}
					catch (StoreException e)
					{
						lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
					}
				}
				else
				{
					CertStore store = (CertStore)obj;

					try
					{
						crls.addAll(PKIXCRLStoreSelector.getCRLs(crlSelect, store));
						foundValidStore = true;
					}
					catch (CertStoreException e)
					{
						lastException = new AnnotatedException("Exception searching in X.509 CRL store.", e);
					}
				}
			}
			if (!foundValidStore && lastException != null)
			{
				throw lastException;
			}
			return crls;
		}

	}

}