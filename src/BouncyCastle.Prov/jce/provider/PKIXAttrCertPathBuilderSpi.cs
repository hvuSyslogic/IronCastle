using System;

namespace org.bouncycastle.jce.provider
{

	using Extension = org.bouncycastle.asn1.x509.Extension;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedBuilderParameters = org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
	using ExtCertPathBuilderException = org.bouncycastle.jce.exception.ExtCertPathBuilderException;
	using Encodable = org.bouncycastle.util.Encodable;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;
	using ExtendedPKIXBuilderParameters = org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
	using ExtendedPKIXParameters = org.bouncycastle.x509.ExtendedPKIXParameters;
	using X509AttributeCertStoreSelector = org.bouncycastle.x509.X509AttributeCertStoreSelector;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;
	using X509CertStoreSelector = org.bouncycastle.x509.X509CertStoreSelector;
	using X509Store = org.bouncycastle.x509.X509Store;

	public class PKIXAttrCertPathBuilderSpi : CertPathBuilderSpi
	{

		/// <summary>
		/// Build and validate a CertPath using the given parameter.
		/// </summary>
		/// <param name="params"> PKIXBuilderParameters object containing all information to
		///            build the CertPath </param>
		public virtual CertPathBuilderResult engineBuild(CertPathParameters @params)
		{
			if (!(@params is PKIXBuilderParameters) && !(@params is ExtendedPKIXBuilderParameters) && !(@params is PKIXExtendedBuilderParameters))
			{
				throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + typeof(PKIXBuilderParameters).getName() + " or " + typeof(PKIXExtendedBuilderParameters).getName() + ".");
			}

			List targetStores = new ArrayList();

			PKIXExtendedBuilderParameters paramsPKIX;
			if (@params is PKIXBuilderParameters)
			{
				PKIXExtendedBuilderParameters.Builder paramsPKIXBldr = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)@params);

				if (@params is ExtendedPKIXParameters)
				{
					ExtendedPKIXBuilderParameters extPKIX = (ExtendedPKIXBuilderParameters)@params;

					paramsPKIXBldr.addExcludedCerts(extPKIX.getExcludedCerts());
					paramsPKIXBldr.setMaxPathLength(extPKIX.getMaxPathLength());
					targetStores = extPKIX.getStores();
				}

				paramsPKIX = paramsPKIXBldr.build();
			}
			else
			{
				paramsPKIX = (PKIXExtendedBuilderParameters)@params;
			}

			Collection targets;
			Iterator targetIter;
			List certPathList = new ArrayList();
			X509AttributeCertificate cert;

			// search target certificates

			Selector certSelect = paramsPKIX.getBaseParameters().getTargetConstraints();
			if (!(certSelect is X509AttributeCertStoreSelector))
			{
				throw new CertPathBuilderException("TargetConstraints must be an instance of " + typeof(X509AttributeCertStoreSelector).getName() + " for " + this.GetType().getName() + " class.");
			}


			try
			{
				targets = findCertificates((X509AttributeCertStoreSelector)certSelect, targetStores);
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathBuilderException("Error finding target attribute certificate.", e);
			}

			if (targets.isEmpty())
			{
				throw new CertPathBuilderException("No attribute certificate found matching targetContraints.");
			}

			CertPathBuilderResult result = null;

			// check all potential target certificates
			targetIter = targets.iterator();
			while (targetIter.hasNext() && result == null)
			{
				cert = (X509AttributeCertificate) targetIter.next();

				X509CertStoreSelector selector = new X509CertStoreSelector();
				Principal[] principals = cert.getIssuer().getPrincipals();
				Set issuers = new HashSet();
				for (int i = 0; i < principals.Length; i++)
				{
					try
					{
						if (principals[i] is X500Principal)
						{
							selector.setSubject(((X500Principal)principals[i]).getEncoded());
						}
						PKIXCertStoreSelector certStoreSelector = (new PKIXCertStoreSelector.Builder(selector)).build();
						issuers.addAll(CertPathValidatorUtilities.findCertificates(certStoreSelector, paramsPKIX.getBaseParameters().getCertStores()));
						issuers.addAll(CertPathValidatorUtilities.findCertificates(certStoreSelector, paramsPKIX.getBaseParameters().getCertificateStores()));
					}
					catch (AnnotatedException e)
					{
						throw new ExtCertPathBuilderException("Public key certificate for attribute certificate cannot be searched.", e);
					}
					catch (IOException e)
					{
						throw new ExtCertPathBuilderException("cannot encode X500Principal.", e);
					}
				}
				if (issuers.isEmpty())
				{
					throw new CertPathBuilderException("Public key certificate for attribute certificate cannot be found.");
				}
				Iterator it = issuers.iterator();
				while (it.hasNext() && result == null)
				{
					result = build(cert, (X509Certificate)it.next(), paramsPKIX, certPathList);
				}
			}

			if (result == null && certPathException != null)
			{
				throw new ExtCertPathBuilderException("Possible certificate chain could not be validated.", certPathException);
			}

			if (result == null && certPathException == null)
			{
				throw new CertPathBuilderException("Unable to find certificate chain.");
			}

			return result;
		}

		private Exception certPathException;

		private CertPathBuilderResult build(X509AttributeCertificate attrCert, X509Certificate tbvCert, PKIXExtendedBuilderParameters pkixParams, List tbvPath)

		{
			// If tbvCert is readily present in tbvPath, it indicates having run
			// into a cycle in the
			// PKI graph.
			if (tbvPath.contains(tbvCert))
			{
				return null;
			}
			// step out, the certificate is not allowed to appear in a certification
			// chain
			if (pkixParams.getExcludedCerts().contains(tbvCert))
			{
				return null;
			}
			// test if certificate path exceeds maximum length
			if (pkixParams.getMaxPathLength() != -1)
			{
				if (tbvPath.size() - 1 > pkixParams.getMaxPathLength())
				{
					return null;
				}
			}

			tbvPath.add(tbvCert);

			CertificateFactory cFact;
			CertPathValidator validator;
			CertPathBuilderResult builderResult = null;

			try
			{
				cFact = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
				validator = CertPathValidator.getInstance("RFC3281", BouncyCastleProvider.PROVIDER_NAME);
			}
			catch (Exception)
			{
				// cannot happen
				throw new RuntimeException("Exception creating support classes.");
			}

			try
			{
				// check whether the issuer of <tbvCert> is a TrustAnchor
				if (CertPathValidatorUtilities.isIssuerTrustAnchor(tbvCert, pkixParams.getBaseParameters().getTrustAnchors(), pkixParams.getBaseParameters().getSigProvider()))
				{
					CertPath certPath;
					PKIXCertPathValidatorResult result;
					try
					{
						certPath = cFact.generateCertPath(tbvPath);
					}
					catch (Exception e)
					{
						throw new AnnotatedException("Certification path could not be constructed from certificate list.", e);
					}

					try
					{
						result = (PKIXCertPathValidatorResult) validator.validate(certPath, pkixParams);
					}
					catch (Exception e)
					{
						throw new AnnotatedException("Certification path could not be validated.", e);
					}

					return new PKIXCertPathBuilderResult(certPath, result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey());

				}
				else
				{
					List stores = new ArrayList();

					stores.addAll(pkixParams.getBaseParameters().getCertificateStores());
					// add additional X.509 stores from locations in certificate
					try
					{
						stores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(tbvCert.getExtensionValue(Extension.issuerAlternativeName.getId()), pkixParams.getBaseParameters().getNamedCertificateStoreMap()));
					}
					catch (CertificateParsingException e)
					{
						throw new AnnotatedException("No additional X.509 stores can be added from certificate locations.", e);
					}
					Collection issuers = new HashSet();
					// try to get the issuer certificate from one
					// of the stores
					try
					{
						issuers.addAll(CertPathValidatorUtilities.findIssuerCerts(tbvCert, pkixParams.getBaseParameters().getCertStores(), stores));
					}
					catch (AnnotatedException e)
					{
						throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", e);
					}
					if (issuers.isEmpty())
					{
						throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
					}
					Iterator it = issuers.iterator();

					while (it.hasNext() && builderResult == null)
					{
						X509Certificate issuer = (X509Certificate) it.next();
						// TODO Use CertPathValidatorUtilities.isSelfIssued(issuer)?
						// if untrusted self signed certificate continue
						if (issuer.getIssuerX500Principal().Equals(issuer.getSubjectX500Principal()))
						{
							continue;
						}
						builderResult = build(attrCert, issuer, pkixParams, tbvPath);
					}
				}
			}
			catch (AnnotatedException e)
			{
				certPathException = new AnnotatedException("No valid certification path could be build.", e);
			}
			if (builderResult == null)
			{
				tbvPath.remove(tbvCert);
			}
			return builderResult;
		}

		protected internal static Collection findCertificates(X509AttributeCertStoreSelector certSelect, List certStores)
		{
			Set certs = new HashSet();
			Iterator iter = certStores.iterator();

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is Store)
				{
					Store certStore = (Store)obj;
					try
					{
						certs.addAll(certStore.getMatches(certSelect));
					}
					catch (StoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
					}
				}
			}
			return certs;
		}
	}

}