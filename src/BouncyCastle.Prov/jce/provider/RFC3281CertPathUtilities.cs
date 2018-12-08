using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using TargetInformation = org.bouncycastle.asn1.x509.TargetInformation;
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using PKIXCRLStore = org.bouncycastle.jcajce.PKIXCRLStore;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedBuilderParameters = org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using ExtCertPathValidatorException = org.bouncycastle.jce.exception.ExtCertPathValidatorException;
	using PKIXAttrCertChecker = org.bouncycastle.x509.PKIXAttrCertChecker;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;
	using X509CertStoreSelector = org.bouncycastle.x509.X509CertStoreSelector;

	public class RFC3281CertPathUtilities
	{

		private static readonly string TARGET_INFORMATION = Extension.targetInformation.getId();

		private static readonly string NO_REV_AVAIL = Extension.noRevAvail.getId();

		private static readonly string CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();

		private static readonly string AUTHORITY_INFO_ACCESS = Extension.authorityInfoAccess.getId();

		protected internal static void processAttrCert7(X509AttributeCertificate attrCert, CertPath certPath, CertPath holderCertPath, PKIXExtendedParameters pkixParams, Set attrCertCheckers)
		{
			// TODO:
			// AA Controls
			// Attribute encryption
			// Proxy
			Set set = attrCert.getCriticalExtensionOIDs();
			// 7.1
			// process extensions

			// target information checked in step 6 / X509AttributeCertStoreSelector
			if (set.contains(TARGET_INFORMATION))
			{
				try
				{
					TargetInformation.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, TARGET_INFORMATION));
				}
				catch (AnnotatedException e)
				{
					throw new ExtCertPathValidatorException("Target information extension could not be read.", e);
				}
				catch (IllegalArgumentException e)
				{
					throw new ExtCertPathValidatorException("Target information extension could not be read.", e);
				}
			}
			set.remove(TARGET_INFORMATION);
			for (Iterator it = attrCertCheckers.iterator(); it.hasNext();)
			{
				((PKIXAttrCertChecker) it.next()).check(attrCert, certPath, holderCertPath, set);
			}
			if (!set.isEmpty())
			{
				throw new CertPathValidatorException("Attribute certificate contains unsupported critical extensions: " + set);
			}
		}

		/// <summary>
		/// Checks if an attribute certificate is revoked.
		/// </summary>
		/// <param name="attrCert"> Attribute certificate to check if it is revoked. </param>
		/// <param name="paramsPKIX"> PKIX parameters. </param>
		/// <param name="issuerCert"> The issuer certificate of the attribute certificate
		///            <code>attrCert</code>. </param>
		/// <param name="validDate"> The date when the certificate revocation status should
		///            be checked. </param>
		/// <param name="certPathCerts"> The certificates of the certification path to be
		///            checked.
		/// </param>
		/// <exception cref="CertPathValidatorException"> if the certificate is revoked or the
		///             status cannot be checked or some error occurs. </exception>
		protected internal static void checkCRLs(X509AttributeCertificate attrCert, PKIXExtendedParameters paramsPKIX, X509Certificate issuerCert, DateTime validDate, List certPathCerts, JcaJceHelper helper)
		{
			if (paramsPKIX.isRevocationEnabled())
			{
				// check if revocation is available
				if (attrCert.getExtensionValue(NO_REV_AVAIL) == null)
				{
					CRLDistPoint crldp = null;
					try
					{
						crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(attrCert, CRL_DISTRIBUTION_POINTS));
					}
					catch (AnnotatedException e)
					{
						throw new CertPathValidatorException("CRL distribution point extension could not be read.", e);
					}

					List crlStores = new ArrayList();

					try
					{
						crlStores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX.getNamedCRLStoreMap()));
					}
					catch (AnnotatedException e)
					{
						throw new CertPathValidatorException("No additional CRL locations could be decoded from CRL distribution point extension.", e);
					}

					PKIXExtendedParameters.Builder bldr = new PKIXExtendedParameters.Builder(paramsPKIX);

					for (Iterator it = crlStores.iterator(); it.hasNext();)
					{
						bldr.addCRLStore((PKIXCRLStore)crlStores);
					}

					paramsPKIX = bldr.build();

					CertStatus certStatus = new CertStatus();
					ReasonsMask reasonsMask = new ReasonsMask();

					AnnotatedException lastException = null;
					bool validCrlFound = false;
					// for each distribution point
					if (crldp != null)
					{
						DistributionPoint[] dps = null;
						try
						{
							dps = crldp.getDistributionPoints();
						}
						catch (Exception e)
						{
							throw new ExtCertPathValidatorException("Distribution points could not be read.", e);
						}
						try
						{
							for (int i = 0; i < dps.Length && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons(); i++)
							{
								PKIXExtendedParameters paramsPKIXClone = (PKIXExtendedParameters)paramsPKIX.clone();

								checkCRL(dps[i], attrCert, paramsPKIXClone, validDate, issuerCert, certStatus, reasonsMask, certPathCerts, helper);
								validCrlFound = true;
							}
						}
						catch (AnnotatedException e)
						{
							lastException = new AnnotatedException("No valid CRL for distribution point found.", e);
						}
					}

					/*
					 * If the revocation status has not been determined, repeat the
					 * process above with any available CRLs not specified in a
					 * distribution point but issued by the certificate issuer.
					 */

					if (certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons())
					{
						try
						{
							/*
							 * assume a DP with both the reasons and the cRLIssuer
							 * fields omitted and a distribution point name of the
							 * certificate issuer.
							 */
							ASN1Primitive issuer = null;
							try
							{

								issuer = (new ASN1InputStream(((X500Principal) attrCert.getIssuer().getPrincipals()[0]).getEncoded())).readObject();
							}
							catch (Exception e)
							{
								throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", e);
							}
							DistributionPoint dp = new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(GeneralName.directoryName, issuer))), null, null);
							PKIXExtendedParameters paramsPKIXClone = (PKIXExtendedParameters) paramsPKIX.clone();
							checkCRL(dp, attrCert, paramsPKIXClone, validDate, issuerCert, certStatus, reasonsMask, certPathCerts, helper);
							validCrlFound = true;
						}
						catch (AnnotatedException e)
						{
							lastException = new AnnotatedException("No valid CRL for distribution point found.", e);
						}
					}

					if (!validCrlFound)
					{
						throw new ExtCertPathValidatorException("No valid CRL found.", lastException);
					}
					if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
					{
						string message = "Attribute certificate revocation after "
							+ certStatus.getRevocationDate();
						message += ", reason: "
							+ RFC3280CertPathUtilities.crlReasons[certStatus.getCertStatus()];
						throw new CertPathValidatorException(message);
					}
					if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == CertStatus.UNREVOKED)
					{
						certStatus.setCertStatus(CertStatus.UNDETERMINED);
					}
					if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
					{
						throw new CertPathValidatorException("Attribute certificate status could not be determined.");
					}

				}
				else
				{
					if (attrCert.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null || attrCert.getExtensionValue(AUTHORITY_INFO_ACCESS) != null)
					{
						throw new CertPathValidatorException("No rev avail extension is set, but also an AC revocation pointer.");
					}
				}
			}
		}

		protected internal static void additionalChecks(X509AttributeCertificate attrCert, Set prohibitedACAttributes, Set necessaryACAttributes)
		{
			// 1
			for (Iterator it = prohibitedACAttributes.iterator(); it.hasNext();)
			{
				string oid = (string) it.next();
				if (attrCert.getAttributes(oid) != null)
				{
					throw new CertPathValidatorException("Attribute certificate contains prohibited attribute: " + oid + ".");
				}
			}
			for (Iterator it = necessaryACAttributes.iterator(); it.hasNext();)
			{
				string oid = (string) it.next();
				if (attrCert.getAttributes(oid) == null)
				{
					throw new CertPathValidatorException("Attribute certificate does not contain necessary attribute: " + oid + ".");
				}
			}
		}

		protected internal static void processAttrCert5(X509AttributeCertificate attrCert, PKIXExtendedParameters pkixParams)
		{
			try
			{
				attrCert.checkValidity(CertPathValidatorUtilities.getValidDate(pkixParams));
			}
			catch (CertificateExpiredException e)
			{
				throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e);
			}
			catch (CertificateNotYetValidException e)
			{
				throw new ExtCertPathValidatorException("Attribute certificate is not valid.", e);
			}
		}

		protected internal static void processAttrCert4(X509Certificate acIssuerCert, Set trustedACIssuers)
		{
			Set set = trustedACIssuers;
			bool trusted = false;
			for (Iterator it = set.iterator(); it.hasNext();)
			{
				TrustAnchor anchor = (TrustAnchor) it.next();
				if (acIssuerCert.getSubjectX500Principal().getName("RFC2253").Equals(anchor.getCAName()) || acIssuerCert.Equals(anchor.getTrustedCert()))
				{
					trusted = true;
				}
			}
			if (!trusted)
			{
				throw new CertPathValidatorException("Attribute certificate issuer is not directly trusted.");
			}
		}

		protected internal static void processAttrCert3(X509Certificate acIssuerCert, PKIXExtendedParameters pkixParams)
		{
			if (acIssuerCert.getKeyUsage() != null && (!acIssuerCert.getKeyUsage()[0] && !acIssuerCert.getKeyUsage()[1]))
			{
				throw new CertPathValidatorException("Attribute certificate issuer public key cannot be used to validate digital signatures.");
			}
			if (acIssuerCert.getBasicConstraints() != -1)
			{
				throw new CertPathValidatorException("Attribute certificate issuer is also a public key certificate issuer.");
			}
		}

		protected internal static CertPathValidatorResult processAttrCert2(CertPath certPath, PKIXExtendedParameters pkixParams)
		{
			CertPathValidator validator = null;
			try
			{
				validator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
			}
			catch (NoSuchProviderException e)
			{
				throw new ExtCertPathValidatorException("Support class could not be created.", e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new ExtCertPathValidatorException("Support class could not be created.", e);
			}
			try
			{
				return validator.validate(certPath, pkixParams);
			}
			catch (CertPathValidatorException e)
			{
				throw new ExtCertPathValidatorException("Certification path for issuer certificate of attribute certificate could not be validated.", e);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				// must be a programming error
				throw new RuntimeException(e.Message);
			}
		}

		/// <summary>
		/// Searches for a holder public key certificate and verifies its
		/// certification path.
		/// </summary>
		/// <param name="attrCert"> the attribute certificate. </param>
		/// <param name="pkixParams"> The PKIX parameters. </param>
		/// <returns> The certificate path of the holder certificate. </returns>
		/// <exception cref="AnnotatedException"> if
		///             <ul>
		///             <li>no public key certificate can be found although holder
		///             information is given by an entity name or a base certificate
		///             ID
		///             <li>support classes cannot be created
		///             <li>no certification path for the public key certificate can
		///             be built
		///             </ul> </exception>
		protected internal static CertPath processAttrCert1(X509AttributeCertificate attrCert, PKIXExtendedParameters pkixParams)
		{
			CertPathBuilderResult result = null;
			// find holder PKCs
			Set holderPKCs = new HashSet();
			if (attrCert.getHolder().getIssuer() != null)
			{
				X509CertSelector selector = new X509CertSelector();
				selector.setSerialNumber(attrCert.getHolder().getSerialNumber());
				Principal[] principals = attrCert.getHolder().getIssuer();
				for (int i = 0; i < principals.Length; i++)
				{
					try
					{
						if (principals[i] is X500Principal)
						{
							selector.setIssuer(((X500Principal)principals[i]).getEncoded());
						}
						holderPKCs.addAll(CertPathValidatorUtilities.findCertificates((new PKIXCertStoreSelector.Builder(selector)).build(), pkixParams.getCertStores()));
					}
					catch (AnnotatedException e)
					{
						throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e);
					}
					catch (IOException e)
					{
						throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e);
					}
				}
				if (holderPKCs.isEmpty())
				{
					throw new CertPathValidatorException("Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
				}
			}
			if (attrCert.getHolder().getEntityNames() != null)
			{
				X509CertStoreSelector selector = new X509CertStoreSelector();
				Principal[] principals = attrCert.getHolder().getEntityNames();
				for (int i = 0; i < principals.Length; i++)
				{
					try
					{
						if (principals[i] is X500Principal)
						{
							selector.setIssuer(((X500Principal) principals[i]).getEncoded());
						}
						holderPKCs.addAll(CertPathValidatorUtilities.findCertificates((new PKIXCertStoreSelector.Builder(selector)).build(), pkixParams.getCertStores()));
					}
					catch (AnnotatedException e)
					{
						throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", e);
					}
					catch (IOException e)
					{
						throw new ExtCertPathValidatorException("Unable to encode X500 principal.", e);
					}
				}
				if (holderPKCs.isEmpty())
				{
					throw new CertPathValidatorException("Public key certificate specified in entity name for attribute certificate cannot be found.");
				}
			}
			// verify cert paths for PKCs
			PKIXExtendedParameters.Builder paramsBldr = new PKIXExtendedParameters.Builder(pkixParams);

			CertPathValidatorException lastException = null;
			for (Iterator it = holderPKCs.iterator(); it.hasNext();)
			{
				X509CertStoreSelector selector = new X509CertStoreSelector();
				selector.setCertificate((X509Certificate) it.next());
				paramsBldr.setTargetConstraints((new PKIXCertStoreSelector.Builder(selector)).build());
				CertPathBuilder builder = null;
				try
				{
					builder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
				}
				catch (NoSuchProviderException e)
				{
					throw new ExtCertPathValidatorException("Support class could not be created.", e);
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new ExtCertPathValidatorException("Support class could not be created.", e);
				}
				try
				{
					result = builder.build((new PKIXExtendedBuilderParameters.Builder(paramsBldr.build())).build());
				}
				catch (CertPathBuilderException e)
				{
					lastException = new ExtCertPathValidatorException("Certification path for public key certificate of attribute certificate could not be build.", e);
				}
				catch (InvalidAlgorithmParameterException e)
				{
					// must be a programming error
					throw new RuntimeException(e.Message);
				}
			}
			if (lastException != null)
			{
				throw lastException;
			}
			return result.getCertPath();
		}

		/// 
		/// <summary>
		/// Checks a distribution point for revocation information for the
		/// certificate <code>attrCert</code>.
		/// </summary>
		/// <param name="dp"> The distribution point to consider. </param>
		/// <param name="attrCert"> The attribute certificate which should be checked. </param>
		/// <param name="paramsPKIX"> PKIX parameters. </param>
		/// <param name="validDate"> The date when the certificate revocation status should
		///            be checked. </param>
		/// <param name="issuerCert"> Certificate to check if it is revoked. </param>
		/// <param name="reasonMask"> The reasons mask which is already checked. </param>
		/// <param name="certPathCerts"> The certificates of the certification path to be
		///            checked. </param>
		/// <exception cref="AnnotatedException"> if the certificate is revoked or the status
		///             cannot be checked or some error occurs. </exception>
		private static void checkCRL(DistributionPoint dp, X509AttributeCertificate attrCert, PKIXExtendedParameters paramsPKIX, DateTime validDate, X509Certificate issuerCert, CertStatus certStatus, ReasonsMask reasonMask, List certPathCerts, JcaJceHelper helper)
		{

			/*
			 * 4.3.6 No Revocation Available
			 * 
			 * The noRevAvail extension, defined in [X.509-2000], allows an AC
			 * issuer to indicate that no revocation information will be made
			 * available for this AC.
			 */
			if (attrCert.getExtensionValue(X509Extensions.NoRevAvail.getId()) != null)
			{
				return;
			}
			DateTime currentDate = new DateTime(System.currentTimeMillis());
			if (validDate.Ticks > currentDate.Ticks)
			{
				throw new AnnotatedException("Validation time is in future.");
			}

			// (a)
			/*
			 * We always get timely valid CRLs, so there is no step (a) (1).
			 * "locally cached" CRLs are assumed to be in getStore(), additional
			 * CRLs must be enabled in the PKIXExtendedParameters and are in
			 * getAdditionalStore()
			 */

			Set crls = CertPathValidatorUtilities.getCompleteCRLs(dp, attrCert, currentDate, paramsPKIX);
			bool validCrlFound = false;
			AnnotatedException lastException = null;
			Iterator crl_iter = crls.iterator();

			while (crl_iter.hasNext() && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonMask.isAllReasons())
			{
				try
				{
					X509CRL crl = (X509CRL) crl_iter.next();

					// (d)
					ReasonsMask interimReasonsMask = RFC3280CertPathUtilities.processCRLD(crl, dp);

					// (e)
					/*
					 * The reasons mask is updated at the end, so only valid CRLs
					 * can update it. If this CRL does not contain new reasons it
					 * must be ignored.
					 */
					if (!interimReasonsMask.hasNewReasons(reasonMask))
					{
						continue;
					}

					// (f)
					Set keys = RFC3280CertPathUtilities.processCRLF(crl, attrCert, null, null, paramsPKIX, certPathCerts, helper);
					// (g)
					PublicKey key = RFC3280CertPathUtilities.processCRLG(crl, keys);

					X509CRL deltaCRL = null;

					if (paramsPKIX.isUseDeltasEnabled())
					{
						// get delta CRLs
						Set deltaCRLs = CertPathValidatorUtilities.getDeltaCRLs(currentDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
						// we only want one valid delta CRL
						// (h)
						deltaCRL = RFC3280CertPathUtilities.processCRLH(deltaCRLs, key);
					}

					/*
					 * CRL must be be valid at the current time, not the validation
					 * time. If a certificate is revoked with reason keyCompromise,
					 * cACompromise, it can be used for forgery, also for the past.
					 * This reason may not be contained in older CRLs.
					 */

					/*
					 * in the chain model signatures stay valid also after the
					 * certificate has been expired, so they do not have to be in
					 * the CRL vality time
					 */

					if (paramsPKIX.getValidityModel() != PKIXExtendedParameters.CHAIN_VALIDITY_MODEL)
					{
						/*
						 * if a certificate has expired, but was revoked, it is not
						 * more in the CRL, so it would be regarded as valid if the
						 * first check is not done
						 */
						if (attrCert.getNotAfter().Ticks < crl.getThisUpdate().getTime())
						{
							throw new AnnotatedException("No valid CRL for current time found.");
						}
					}

					RFC3280CertPathUtilities.processCRLB1(dp, attrCert, crl);

					// (b) (2)
					RFC3280CertPathUtilities.processCRLB2(dp, attrCert, crl);

					// (c)
					RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);

					// (i)
					RFC3280CertPathUtilities.processCRLI(validDate, deltaCRL, attrCert, certStatus, paramsPKIX);

					// (j)
					RFC3280CertPathUtilities.processCRLJ(validDate, crl, attrCert, certStatus);

					// (k)
					if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
					{
						certStatus.setCertStatus(CertStatus.UNREVOKED);
					}

					// update reasons mask
					reasonMask.addReasons(interimReasonsMask);
					validCrlFound = true;
				}
				catch (AnnotatedException e)
				{
					lastException = e;
				}
			}
			if (!validCrlFound)
			{
				throw lastException;
			}
		}
	}

}