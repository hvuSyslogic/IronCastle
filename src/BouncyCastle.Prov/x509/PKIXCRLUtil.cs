using System;

namespace org.bouncycastle.x509
{

	using AnnotatedException = org.bouncycastle.jce.provider.AnnotatedException;
	using StoreException = org.bouncycastle.util.StoreException;

	public class PKIXCRLUtil
	{
		public virtual Set findCRLs(X509CRLStoreSelector crlselect, ExtendedPKIXParameters paramsPKIX, DateTime currentDate)
		{
			Set initialSet = new HashSet();

			// get complete CRL(s)
			try
			{
				initialSet.addAll(findCRLs(crlselect, paramsPKIX.getAdditionalStores()));
				initialSet.addAll(findCRLs(crlselect, paramsPKIX.getStores()));
				initialSet.addAll(findCRLs(crlselect, paramsPKIX.getCertStores()));
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Exception obtaining complete CRLs.", e);
			}

			Set finalSet = new HashSet();
			DateTime validityDate = currentDate;

			if (paramsPKIX.getDate() != null)
			{
				validityDate = paramsPKIX.getDate();
			}

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

		public virtual Set findCRLs(X509CRLStoreSelector crlselect, PKIXParameters paramsPKIX)
		{
			Set completeSet = new HashSet();

			// get complete CRL(s)
			try
			{
				completeSet.addAll(findCRLs(crlselect, paramsPKIX.getCertStores()));
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Exception obtaining complete CRLs.", e);
			}

			return completeSet;
		}

	/// <summary>
	/// Return a Collection of all CRLs found in the X509Store's that are
	/// matching the crlSelect criteriums.
	/// </summary>
	/// <param name="crlSelect"> a <seealso cref="X509CRLStoreSelector"/> object that will be used
	///            to select the CRLs </param>
	/// <param name="crlStores"> a List containing only
	///            <seealso cref="org.bouncycastle.x509.X509Store  X509Store"/> objects.
	///            These are used to search for CRLs
	/// </param>
	/// <returns> a Collection of all found <seealso cref="java.security.cert.X509CRL X509CRL"/> objects. May be
	///         empty but never <code>null</code>. </returns>
		private Collection findCRLs(X509CRLStoreSelector crlSelect, List crlStores)
		{
			Set crls = new HashSet();
			Iterator iter = crlStores.iterator();

			AnnotatedException lastException = null;
			bool foundValidStore = false;

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is X509Store)
				{
					X509Store store = (X509Store)obj;

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
						crls.addAll(store.getCRLs(crlSelect));
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