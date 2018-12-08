using System;

namespace org.bouncycastle.jce.provider
{

	using Extension = org.bouncycastle.asn1.x509.Extension;
	using PKIXCertStore = org.bouncycastle.jcajce.PKIXCertStore;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedBuilderParameters = org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using CertificateFactory = org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
	using ExtCertPathBuilderException = org.bouncycastle.jce.exception.ExtCertPathBuilderException;
	using ExtendedPKIXBuilderParameters = org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
	using ExtendedPKIXParameters = org.bouncycastle.x509.ExtendedPKIXParameters;

	/// <summary>
	/// Implements the PKIX CertPathBuilding algorithm for BouncyCastle.
	/// </summary>
	/// <seealso cref= CertPathBuilderSpi </seealso>
	public class PKIXCertPathBuilderSpi : CertPathBuilderSpi
	{
		/// <summary>
		/// Build and validate a CertPath using the given parameter.
		/// </summary>
		/// <param name="params"> PKIXBuilderParameters object containing all information to
		///            build the CertPath </param>
		public virtual CertPathBuilderResult engineBuild(CertPathParameters @params)
		{
			PKIXExtendedBuilderParameters paramsPKIX;
			if (@params is PKIXBuilderParameters)
			{
				PKIXExtendedParameters.Builder paramsPKIXBldr = new PKIXExtendedParameters.Builder((PKIXBuilderParameters)@params);
				PKIXExtendedBuilderParameters.Builder paramsBldrPKIXBldr;

				if (@params is ExtendedPKIXParameters)
				{
					ExtendedPKIXBuilderParameters extPKIX = (ExtendedPKIXBuilderParameters)@params;

					for (Iterator it = extPKIX.getAdditionalStores().iterator(); it.hasNext();)
					{
						 paramsPKIXBldr.addCertificateStore((PKIXCertStore)it.next());
					}
					paramsBldrPKIXBldr = new PKIXExtendedBuilderParameters.Builder(paramsPKIXBldr.build());

					paramsBldrPKIXBldr.addExcludedCerts(extPKIX.getExcludedCerts());
					paramsBldrPKIXBldr.setMaxPathLength(extPKIX.getMaxPathLength());
				}
				else
				{
					paramsBldrPKIXBldr = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)@params);
				}

				paramsPKIX = paramsBldrPKIXBldr.build();
			}
			else if (@params is PKIXExtendedBuilderParameters)
			{
				paramsPKIX = (PKIXExtendedBuilderParameters)@params;
			}
			else
			{
				throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + typeof(PKIXBuilderParameters).getName() + " or " + typeof(PKIXExtendedBuilderParameters).getName() + ".");
			}

			Collection targets;
			Iterator targetIter;
			List certPathList = new ArrayList();
			X509Certificate cert;

			// search target certificates

			PKIXCertStoreSelector certSelect = paramsPKIX.getBaseParameters().getTargetConstraints();

			try
			{
				targets = CertPathValidatorUtilities.findCertificates(certSelect, paramsPKIX.getBaseParameters().getCertificateStores());
				targets.addAll(CertPathValidatorUtilities.findCertificates(certSelect, paramsPKIX.getBaseParameters().getCertStores()));
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathBuilderException("Error finding target certificate.", e);
			}

			if (targets.isEmpty())
			{

				throw new CertPathBuilderException("No certificate found matching targetContraints.");
			}

			CertPathBuilderResult result = null;

			// check all potential target certificates
			targetIter = targets.iterator();
			while (targetIter.hasNext() && result == null)
			{
				cert = (X509Certificate) targetIter.next();
				result = build(cert, paramsPKIX, certPathList);
			}

			if (result == null && certPathException != null)
			{
				if (certPathException is AnnotatedException)
				{
					throw new CertPathBuilderException(certPathException.Message, certPathException.InnerException);
				}
				throw new CertPathBuilderException("Possible certificate chain could not be validated.", certPathException);
			}

			if (result == null && certPathException == null)
			{
				throw new CertPathBuilderException("Unable to find certificate chain.");
			}

			return result;
		}

		private Exception certPathException;

		public virtual CertPathBuilderResult build(X509Certificate tbvCert, PKIXExtendedBuilderParameters pkixParams, List tbvPath)
		{
			// If tbvCert is readily present in tbvPath, it indicates having run
			// into a cycle in the
			// PKI graph.
			if (tbvPath.contains(tbvCert))
			{
				return null;
			}
			// step out, the certificate is not allowed to appear in a certification
			// chain.
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
			PKIXCertPathValidatorSpi validator;
			CertPathBuilderResult builderResult = null;

			try
			{
				cFact = new CertificateFactory();
				validator = new PKIXCertPathValidatorSpi();
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
					// exception message from possibly later tried certification
					// chains
					CertPath certPath = null;
					PKIXCertPathValidatorResult result = null;
					try
					{
						certPath = cFact.engineGenerateCertPath(tbvPath);
					}
					catch (Exception e)
					{
						throw new AnnotatedException("Certification path could not be constructed from certificate list.", e);
					}

					try
					{
						result = (PKIXCertPathValidatorResult) validator.engineValidate(certPath, pkixParams);
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
						builderResult = build(issuer, pkixParams, tbvPath);
					}
				}
			}
			catch (AnnotatedException e)
			{
				certPathException = e;
			}
			if (builderResult == null)
			{
				tbvPath.remove(tbvCert);
			}
			return builderResult;
		}

	}

}