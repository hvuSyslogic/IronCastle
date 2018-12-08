using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using RDN = org.bouncycastle.asn1.x500.RDN;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using BCStyle = org.bouncycastle.asn1.x500.style.BCStyle;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using GeneralSubtree = org.bouncycastle.asn1.x509.GeneralSubtree;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using NameConstraints = org.bouncycastle.asn1.x509.NameConstraints;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using PKIXCRLStore = org.bouncycastle.jcajce.PKIXCRLStore;
	using PKIXCRLStoreSelector = org.bouncycastle.jcajce.PKIXCRLStoreSelector;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedBuilderParameters = org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using ExtCertPathValidatorException = org.bouncycastle.jce.exception.ExtCertPathValidatorException;
	using Arrays = org.bouncycastle.util.Arrays;

	public class RFC3280CertPathUtilities
	{
		private static readonly PKIXCRLUtil CRL_UTIL = new PKIXCRLUtil();

		/// <summary>
		/// If the complete CRL includes an issuing distribution point (IDP) CRL
		/// extension check the following:
		/// <para>
		/// (i) If the distribution point name is present in the IDP CRL extension
		/// and the distribution field is present in the DP, then verify that one of
		/// the names in the IDP matches one of the names in the DP. If the
		/// distribution point name is present in the IDP CRL extension and the
		/// distribution field is omitted from the DP, then verify that one of the
		/// names in the IDP matches one of the names in the cRLIssuer field of the
		/// DP.
		/// </para>
		/// <para>
		/// (ii) If the onlyContainsUserCerts boolean is asserted in the IDP CRL
		/// extension, verify that the certificate does not include the basic
		/// constraints extension with the cA boolean asserted.
		/// </para>
		/// <para>
		/// (iii) If the onlyContainsCACerts boolean is asserted in the IDP CRL
		/// extension, verify that the certificate includes the basic constraints
		/// extension with the cA boolean asserted.
		/// </para>
		/// <para>
		/// (iv) Verify that the onlyContainsAttributeCerts boolean is not asserted.
		/// </para>
		/// </summary>
		/// <param name="dp">   The distribution point. </param>
		/// <param name="cert"> The certificate. </param>
		/// <param name="crl">  The CRL. </param>
		/// <exception cref="AnnotatedException"> if one of the conditions is not met or an error occurs. </exception>
		protected internal static void processCRLB2(DistributionPoint dp, object cert, X509CRL crl)
		{
			IssuingDistributionPoint idp = null;
			try
			{
				idp = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(crl, RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("Issuing distribution point extension could not be decoded.", e);
			}
			// (b) (2) (i)
			// distribution point name is present
			if (idp != null)
			{
				if (idp.getDistributionPoint() != null)
				{
					// make list of names
					DistributionPointName dpName = IssuingDistributionPoint.getInstance(idp).getDistributionPoint();
					List names = new ArrayList();

					if (dpName.getType() == DistributionPointName.FULL_NAME)
					{
						GeneralName[] genNames = GeneralNames.getInstance(dpName.getName()).getNames();
						for (int j = 0; j < genNames.Length; j++)
						{
							names.add(genNames[j]);
						}
					}
					if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
					{
						ASN1EncodableVector vec = new ASN1EncodableVector();
						try
						{
							Enumeration e = ASN1Sequence.getInstance(PrincipalUtils.getIssuerPrincipal(crl)).getObjects();
							while (e.hasMoreElements())
							{
								vec.add((ASN1Encodable)e.nextElement());
							}
						}
						catch (Exception e)
						{
							throw new AnnotatedException("Could not read CRL issuer.", e);
						}
						vec.add(dpName.getName());
						names.add(new GeneralName(X500Name.getInstance(new DERSequence(vec))));
					}
					bool matches = false;
					// verify that one of the names in the IDP matches one
					// of the names in the DP.
					if (dp.getDistributionPoint() != null)
					{
						dpName = dp.getDistributionPoint();
						GeneralName[] genNames = null;
						if (dpName.getType() == DistributionPointName.FULL_NAME)
						{
							genNames = GeneralNames.getInstance(dpName.getName()).getNames();
						}
						if (dpName.getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
						{
							if (dp.getCRLIssuer() != null)
							{
								genNames = dp.getCRLIssuer().getNames();
							}
							else
							{
								genNames = new GeneralName[1];
								try
								{
									genNames[0] = new GeneralName(X500Name.getInstance(PrincipalUtils.getEncodedIssuerPrincipal(cert).getEncoded()));
								}
								catch (Exception e)
								{
									throw new AnnotatedException("Could not read certificate issuer.", e);
								}
							}
							for (int j = 0; j < genNames.Length; j++)
							{
								Enumeration e = ASN1Sequence.getInstance(genNames[j].getName().toASN1Primitive()).getObjects();
								ASN1EncodableVector vec = new ASN1EncodableVector();
								while (e.hasMoreElements())
								{
									vec.add((ASN1Encodable)e.nextElement());
								}
								vec.add(dpName.getName());
								genNames[j] = new GeneralName(X500Name.getInstance(new DERSequence(vec)));
							}
						}
						if (genNames != null)
						{
							for (int j = 0; j < genNames.Length; j++)
							{
								if (names.contains(genNames[j]))
								{
									matches = true;
									break;
								}
							}
						}
						if (!matches)
						{
							throw new AnnotatedException("No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
						}
					}
					// verify that one of the names in
					// the IDP matches one of the names in the cRLIssuer field of
					// the DP
					else
					{
						if (dp.getCRLIssuer() == null)
						{
							throw new AnnotatedException("Either the cRLIssuer or the distributionPoint field must " + "be contained in DistributionPoint.");
						}
						GeneralName[] genNames = dp.getCRLIssuer().getNames();
						for (int j = 0; j < genNames.Length; j++)
						{
							if (names.contains(genNames[j]))
							{
								matches = true;
								break;
							}
						}
						if (!matches)
						{
							throw new AnnotatedException("No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
						}
					}
				}
				BasicConstraints bc = null;
				try
				{
					bc = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue((X509Extension)cert, BASIC_CONSTRAINTS));
				}
				catch (Exception e)
				{
					throw new AnnotatedException("Basic constraints extension could not be decoded.", e);
				}

				if (cert is X509Certificate)
				{
					// (b) (2) (ii)
					if (idp.onlyContainsUserCerts() && (bc != null && bc.isCA()))
					{
						throw new AnnotatedException("CA Cert CRL only contains user certificates.");
					}

					// (b) (2) (iii)
					if (idp.onlyContainsCACerts() && (bc == null || !bc.isCA()))
					{
						throw new AnnotatedException("End CRL only contains CA certificates.");
					}
				}

				// (b) (2) (iv)
				if (idp.onlyContainsAttributeCerts())
				{
					throw new AnnotatedException("onlyContainsAttributeCerts boolean is asserted.");
				}
			}
		}

		/// <summary>
		/// If the DP includes cRLIssuer, then verify that the issuer field in the
		/// complete CRL matches cRLIssuer in the DP and that the complete CRL
		/// contains an issuing distribution point extension with the indirectCRL
		/// boolean asserted. Otherwise, verify that the CRL issuer matches the
		/// certificate issuer.
		/// </summary>
		/// <param name="dp">   The distribution point. </param>
		/// <param name="cert"> The certificate ot attribute certificate. </param>
		/// <param name="crl">  The CRL for <code>cert</code>. </param>
		/// <exception cref="AnnotatedException"> if one of the above conditions does not apply or an error
		///                            occurs. </exception>
		protected internal static void processCRLB1(DistributionPoint dp, object cert, X509CRL crl)
		{
			ASN1Primitive idp = CertPathValidatorUtilities.getExtensionValue(crl, ISSUING_DISTRIBUTION_POINT);
			bool isIndirect = false;
			if (idp != null)
			{
				if (IssuingDistributionPoint.getInstance(idp).isIndirectCRL())
				{
					isIndirect = true;
				}
			}
			byte[] issuerBytes;

			try
			{
				issuerBytes = PrincipalUtils.getIssuerPrincipal(crl).getEncoded();
			}
			catch (IOException e)
			{
				throw new AnnotatedException("Exception encoding CRL issuer: " + e.Message, e);
			}

			bool matchIssuer = false;
			if (dp.getCRLIssuer() != null)
			{
				GeneralName[] genNames = dp.getCRLIssuer().getNames();
				for (int j = 0; j < genNames.Length; j++)
				{
					if (genNames[j].getTagNo() == GeneralName.directoryName)
					{
						try
						{
							if (Arrays.areEqual(genNames[j].getName().toASN1Primitive().getEncoded(), issuerBytes))
							{
								matchIssuer = true;
							}
						}
						catch (IOException e)
						{
							throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", e);
						}
					}
				}
				if (matchIssuer && !isIndirect)
				{
					throw new AnnotatedException("Distribution point contains cRLIssuer field but CRL is not indirect.");
				}
				if (!matchIssuer)
				{
					throw new AnnotatedException("CRL issuer of CRL does not match CRL issuer of distribution point.");
				}
			}
			else
			{
				if (PrincipalUtils.getIssuerPrincipal(crl).Equals(PrincipalUtils.getEncodedIssuerPrincipal(cert)))
				{
					matchIssuer = true;
				}
			}
			if (!matchIssuer)
			{
				throw new AnnotatedException("Cannot find matching CRL issuer for certificate.");
			}
		}

		protected internal static ReasonsMask processCRLD(X509CRL crl, DistributionPoint dp)
		{
			IssuingDistributionPoint idp = null;
			try
			{
				idp = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(crl, RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("Issuing distribution point extension could not be decoded.", e);
			}
			// (d) (1)
			if (idp != null && idp.getOnlySomeReasons() != null && dp.getReasons() != null)
			{
				return (new ReasonsMask(dp.getReasons())).intersect(new ReasonsMask(idp.getOnlySomeReasons()));
			}
			// (d) (4)
			if ((idp == null || idp.getOnlySomeReasons() == null) && dp.getReasons() == null)
			{
				return ReasonsMask.allReasons;
			}
			// (d) (2) and (d)(3)
			return (dp.getReasons() == null ? ReasonsMask.allReasons : new ReasonsMask(dp.getReasons())).intersect(idp == null ? ReasonsMask.allReasons : new ReasonsMask(idp.getOnlySomeReasons()));

		}

		public static readonly string CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();

		public static readonly string POLICY_MAPPINGS = Extension.policyMappings.getId();

		public static readonly string INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();

		public static readonly string ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();

		public static readonly string FRESHEST_CRL = Extension.freshestCRL.getId();

		public static readonly string DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();

		public static readonly string POLICY_CONSTRAINTS = Extension.policyConstraints.getId();

		public static readonly string BASIC_CONSTRAINTS = Extension.basicConstraints.getId();

		public static readonly string CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();

		public static readonly string SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();

		public static readonly string NAME_CONSTRAINTS = Extension.nameConstraints.getId();

		public static readonly string AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();

		public static readonly string KEY_USAGE = Extension.keyUsage.getId();

		public static readonly string CRL_NUMBER = Extension.cRLNumber.getId();

		public const string ANY_POLICY = "2.5.29.32.0";

		/*
		 * key usage bits
		 */
		protected internal const int KEY_CERT_SIGN = 5;

		protected internal const int CRL_SIGN = 6;

		/// <summary>
		/// Obtain and validate the certification path for the complete CRL issuer.
		/// If a key usage extension is present in the CRL issuer's certificate,
		/// verify that the cRLSign bit is set.
		/// </summary>
		/// <param name="crl">                CRL which contains revocation information for the certificate
		///                           <code>cert</code>. </param>
		/// <param name="cert">               The attribute certificate or certificate to check if it is
		///                           revoked. </param>
		/// <param name="defaultCRLSignCert"> The issuer certificate of the certificate <code>cert</code>. </param>
		/// <param name="defaultCRLSignKey">  The public key of the issuer certificate
		///                           <code>defaultCRLSignCert</code>. </param>
		/// <param name="paramsPKIX">         paramsPKIX PKIX parameters. </param>
		/// <param name="certPathCerts">      The certificates on the certification path. </param>
		/// <returns> A <code>Set</code> with all keys of possible CRL issuer
		///         certificates. </returns>
		/// <exception cref="AnnotatedException"> if the CRL is not valid or the status cannot be checked or
		///                            some error occurs. </exception>
		protected internal static Set processCRLF(X509CRL crl, object cert, X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey, PKIXExtendedParameters paramsPKIX, List certPathCerts, JcaJceHelper helper)
		{
			// (f)

			// get issuer from CRL
			X509CertSelector certSelector = new X509CertSelector();
			try
			{
				byte[] issuerPrincipal = PrincipalUtils.getIssuerPrincipal(crl).getEncoded();
				certSelector.setSubject(issuerPrincipal);
			}
			catch (IOException e)
			{
				throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate for CRL could not be set.", e);
			}

			PKIXCertStoreSelector selector = (new PKIXCertStoreSelector.Builder(certSelector)).build();

			// get CRL signing certs
			Collection coll;
			try
			{
				coll = CertPathValidatorUtilities.findCertificates(selector, paramsPKIX.getCertificateStores());
				coll.addAll(CertPathValidatorUtilities.findCertificates(selector, paramsPKIX.getCertStores()));
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Issuer certificate for CRL cannot be searched.", e);
			}

			coll.add(defaultCRLSignCert);

			Iterator cert_it = coll.iterator();

			List validCerts = new ArrayList();
			List validKeys = new ArrayList();

			while (cert_it.hasNext())
			{
				X509Certificate signingCert = (X509Certificate)cert_it.next();

				/*
				 * CA of the certificate, for which this CRL is checked, has also
				 * signed CRL, so skip the path validation, because is already done
				 */
				if (signingCert.Equals(defaultCRLSignCert))
				{
					validCerts.add(signingCert);
					validKeys.add(defaultCRLSignKey);
					continue;
				}
				try
				{
					PKIXCertPathBuilderSpi builder = new PKIXCertPathBuilderSpi();
					X509CertSelector tmpCertSelector = new X509CertSelector();
					tmpCertSelector.setCertificate(signingCert);

					PKIXExtendedParameters.Builder paramsBuilder = (new PKIXExtendedParameters.Builder(paramsPKIX)).setTargetConstraints((new PKIXCertStoreSelector.Builder(tmpCertSelector)).build());

					/*
					 * if signingCert is placed not higher on the cert path a
					 * dependency loop results. CRL for cert is checked, but
					 * signingCert is needed for checking the CRL which is dependent
					 * on checking cert because it is higher in the cert path and so
					 * signing signingCert transitively. so, revocation is disabled,
					 * forgery attacks of the CRL are detected in this outer loop
					 * for all other it must be enabled to prevent forgery attacks
					 */
					if (certPathCerts.contains(signingCert))
					{
						paramsBuilder.setRevocationEnabled(false);
					}
					else
					{
						paramsBuilder.setRevocationEnabled(true);
					}

					PKIXExtendedBuilderParameters extParams = (new PKIXExtendedBuilderParameters.Builder(paramsBuilder.build())).build();

					List certs = builder.engineBuild(extParams).getCertPath().getCertificates();
					validCerts.add(signingCert);
					validKeys.add(CertPathValidatorUtilities.getNextWorkingKey(certs, 0, helper));
				}
				catch (CertPathBuilderException e)
				{
					throw new AnnotatedException("CertPath for CRL signer failed to validate.", e);
				}
				catch (CertPathValidatorException e)
				{
					throw new AnnotatedException("Public key of issuer certificate of CRL could not be retrieved.", e);
				}
				catch (Exception e)
				{
					throw new AnnotatedException(e.Message);
				}
			}

			Set checkKeys = new HashSet();

			AnnotatedException lastException = null;
			for (int i = 0; i < validCerts.size(); i++)
			{
				X509Certificate signCert = (X509Certificate)validCerts.get(i);
				bool[] keyusage = signCert.getKeyUsage();

				if (keyusage != null && (keyusage.Length < 7 || !keyusage[CRL_SIGN]))
				{
					lastException = new AnnotatedException("Issuer certificate key usage extension does not permit CRL signing.");
				}
				else
				{
					checkKeys.add(validKeys.get(i));
				}
			}

			if (checkKeys.isEmpty() && lastException == null)
			{
				throw new AnnotatedException("Cannot find a valid issuer certificate.");
			}
			if (checkKeys.isEmpty() && lastException != null)
			{
				throw lastException;
			}

			return checkKeys;
		}

		protected internal static PublicKey processCRLG(X509CRL crl, Set keys)
		{
			Exception lastException = null;
			for (Iterator it = keys.iterator(); it.hasNext();)
			{
				PublicKey key = (PublicKey)it.next();
				try
				{
					crl.verify(key);
					return key;
				}
				catch (Exception e)
				{
					lastException = e;
				}
			}
			throw new AnnotatedException("Cannot verify CRL.", lastException);
		}

		protected internal static X509CRL processCRLH(Set deltacrls, PublicKey key)
		{
			Exception lastException = null;

			for (Iterator it = deltacrls.iterator(); it.hasNext();)
			{
				X509CRL crl = (X509CRL)it.next();
				try
				{
					crl.verify(key);
					return crl;
				}
				catch (Exception e)
				{
					lastException = e;
				}
			}

			if (lastException != null)
			{
				throw new AnnotatedException("Cannot verify delta CRL.", lastException);
			}
			return null;
		}

		protected internal static Set processCRLA1i(DateTime currentDate, PKIXExtendedParameters paramsPKIX, X509Certificate cert, X509CRL crl)
		{
			Set set = new HashSet();
			if (paramsPKIX.isUseDeltasEnabled())
			{
				CRLDistPoint freshestCRL = null;
				try
				{
					freshestCRL = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, FRESHEST_CRL));
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Freshest CRL extension could not be decoded from certificate.", e);
				}
				if (freshestCRL == null)
				{
					try
					{
						freshestCRL = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(crl, FRESHEST_CRL));
					}
					catch (AnnotatedException e)
					{
						throw new AnnotatedException("Freshest CRL extension could not be decoded from CRL.", e);
					}
				}
				if (freshestCRL != null)
				{
					List crlStores = new ArrayList();

					crlStores.addAll(paramsPKIX.getCRLStores());

					try
					{
						crlStores.addAll(CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(freshestCRL, paramsPKIX.getNamedCRLStoreMap()));
					}
					catch (AnnotatedException e)
					{
						throw new AnnotatedException("No new delta CRL locations could be added from Freshest CRL extension.", e);
					}

					// get delta CRL(s)
					try
					{
						set.addAll(CertPathValidatorUtilities.getDeltaCRLs(currentDate, crl, paramsPKIX.getCertStores(), crlStores));
					}
					catch (AnnotatedException e)
					{
						throw new AnnotatedException("Exception obtaining delta CRLs.", e);
					}
				}
			}
			return set;
		}

		protected internal static Set[] processCRLA1ii(DateTime currentDate, PKIXExtendedParameters paramsPKIX, X509Certificate cert, X509CRL crl)
		{
			Set deltaSet = new HashSet();
			X509CRLSelector crlselect = new X509CRLSelector();
			crlselect.setCertificateChecking(cert);

			try
			{
				crlselect.addIssuerName(PrincipalUtils.getIssuerPrincipal(crl).getEncoded());
			}
			catch (IOException e)
			{
				throw new AnnotatedException("Cannot extract issuer from CRL." + e, e);
			}

			PKIXCRLStoreSelector extSelect = (new PKIXCRLStoreSelector.Builder(crlselect)).setCompleteCRLEnabled(true).build();

			DateTime validityDate = currentDate;

			if (paramsPKIX.getDate() != null)
			{
				validityDate = paramsPKIX.getDate();
			}

			Set completeSet = CRL_UTIL.findCRLs(extSelect, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());

			if (paramsPKIX.isUseDeltasEnabled())
			{
				// get delta CRL(s)
				try
				{
					deltaSet.addAll(CertPathValidatorUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores()));
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Exception obtaining delta CRLs.", e);
				}
			}
			return new Set[] {completeSet, deltaSet};
		}



		/// <summary>
		/// If use-deltas is set, verify the issuer and scope of the delta CRL.
		/// </summary>
		/// <param name="deltaCRL">    The delta CRL. </param>
		/// <param name="completeCRL"> The complete CRL. </param>
		/// <param name="pkixParams">  The PKIX paramaters. </param>
		/// <exception cref="AnnotatedException"> if an exception occurs. </exception>
		protected internal static void processCRLC(X509CRL deltaCRL, X509CRL completeCRL, PKIXExtendedParameters pkixParams)
		{
			if (deltaCRL == null)
			{
				return;
			}
			IssuingDistributionPoint completeidp = null;
			try
			{
				completeidp = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(completeCRL, RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("Issuing distribution point extension could not be decoded.", e);
			}

			if (pkixParams.isUseDeltasEnabled())
			{
				// (c) (1)
				if (!PrincipalUtils.getIssuerPrincipal(deltaCRL).Equals(PrincipalUtils.getIssuerPrincipal(completeCRL)))
				{
					throw new AnnotatedException("Complete CRL issuer does not match delta CRL issuer.");
				}

				// (c) (2)
				IssuingDistributionPoint deltaidp = null;
				try
				{
					deltaidp = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(deltaCRL, ISSUING_DISTRIBUTION_POINT));
				}
				catch (Exception e)
				{
					throw new AnnotatedException("Issuing distribution point extension from delta CRL could not be decoded.", e);
				}

				bool match = false;
				if (completeidp == null)
				{
					if (deltaidp == null)
					{
						match = true;
					}
				}
				else
				{
					if (completeidp.Equals(deltaidp))
					{
						match = true;
					}
				}
				if (!match)
				{
					throw new AnnotatedException("Issuing distribution point extension from delta CRL and complete CRL does not match.");
				}

				// (c) (3)
				ASN1Primitive completeKeyIdentifier = null;
				try
				{
					completeKeyIdentifier = CertPathValidatorUtilities.getExtensionValue(completeCRL, AUTHORITY_KEY_IDENTIFIER);
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Authority key identifier extension could not be extracted from complete CRL.", e);
				}

				ASN1Primitive deltaKeyIdentifier = null;
				try
				{
					deltaKeyIdentifier = CertPathValidatorUtilities.getExtensionValue(deltaCRL, AUTHORITY_KEY_IDENTIFIER);
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Authority key identifier extension could not be extracted from delta CRL.", e);
				}

				if (completeKeyIdentifier == null)
				{
					throw new AnnotatedException("CRL authority key identifier is null.");
				}

				if (deltaKeyIdentifier == null)
				{
					throw new AnnotatedException("Delta CRL authority key identifier is null.");
				}

				if (!completeKeyIdentifier.Equals(deltaKeyIdentifier))
				{
					throw new AnnotatedException("Delta CRL authority key identifier does not match complete CRL authority key identifier.");
				}
			}
		}

		protected internal static void processCRLI(DateTime validDate, X509CRL deltacrl, object cert, CertStatus certStatus, PKIXExtendedParameters pkixParams)
		{
			if (pkixParams.isUseDeltasEnabled() && deltacrl != null)
			{
				CertPathValidatorUtilities.getCertStatus(validDate, deltacrl, cert, certStatus);
			}
		}

		protected internal static void processCRLJ(DateTime validDate, X509CRL completecrl, object cert, CertStatus certStatus)
		{
			if (certStatus.getCertStatus() == CertStatus.UNREVOKED)
			{
				CertPathValidatorUtilities.getCertStatus(validDate, completecrl, cert, certStatus);
			}
		}

		protected internal static PKIXPolicyNode prepareCertB(CertPath certPath, int index, List[] policyNodes, PKIXPolicyNode validPolicyTree, int policyMapping)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			int n = certs.size();
			// i as defined in the algorithm description
			int i = n - index;
			// (b)
			//
			ASN1Sequence pm = null;
			try
			{
				pm = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.POLICY_MAPPINGS));
			}
			catch (AnnotatedException ex)
			{
				throw new ExtCertPathValidatorException("Policy mappings extension could not be decoded.", ex, certPath, index);
			}
			PKIXPolicyNode _validPolicyTree = validPolicyTree;
			if (pm != null)
			{
				ASN1Sequence mappings = (ASN1Sequence)pm;
				Map m_idp = new HashMap();
				Set s_idp = new HashSet();

				for (int j = 0; j < mappings.size(); j++)
				{
					ASN1Sequence mapping = (ASN1Sequence)mappings.getObjectAt(j);
					string id_p = ((ASN1ObjectIdentifier)mapping.getObjectAt(0)).getId();
					string sd_p = ((ASN1ObjectIdentifier)mapping.getObjectAt(1)).getId();
					Set tmp;

					if (!m_idp.containsKey(id_p))
					{
						tmp = new HashSet();
						tmp.add(sd_p);
						m_idp.put(id_p, tmp);
						s_idp.add(id_p);
					}
					else
					{
						tmp = (Set)m_idp.get(id_p);
						tmp.add(sd_p);
					}
				}

				Iterator it_idp = s_idp.iterator();
				while (it_idp.hasNext())
				{
					string id_p = (string)it_idp.next();

					//
					// (1)
					//
					if (policyMapping > 0)
					{
						bool idp_found = false;
						Iterator nodes_i = policyNodes[i].iterator();
						while (nodes_i.hasNext())
						{
							PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
							if (node.getValidPolicy().Equals(id_p))
							{
								idp_found = true;
								node.expectedPolicies = (Set)m_idp.get(id_p);
								break;
							}
						}

						if (!idp_found)
						{
							nodes_i = policyNodes[i].iterator();
							while (nodes_i.hasNext())
							{
								PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
								if (RFC3280CertPathUtilities.ANY_POLICY.Equals(node.getValidPolicy()))
								{
									Set pq = null;
									ASN1Sequence policies = null;
									try
									{
										policies = (ASN1Sequence)CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
									}
									catch (AnnotatedException e)
									{
										throw new ExtCertPathValidatorException("Certificate policies extension could not be decoded.", e, certPath, index);
									}
									Enumeration e = policies.getObjects();
									while (e.hasMoreElements())
									{
										PolicyInformation pinfo = null;
										try
										{
											pinfo = PolicyInformation.getInstance(e.nextElement());
										}
										catch (Exception ex)
										{
											throw new CertPathValidatorException("Policy information could not be decoded.", ex, certPath, index);
										}
										if (RFC3280CertPathUtilities.ANY_POLICY.Equals(pinfo.getPolicyIdentifier().getId()))
										{
											try
											{
												pq = CertPathValidatorUtilities.getQualifierSet(pinfo.getPolicyQualifiers());
											}
											catch (CertPathValidatorException ex)
											{

												throw new ExtCertPathValidatorException("Policy qualifier info set could not be decoded.", ex, certPath, index);
											}
											break;
										}
									}
									bool ci = false;
									if (cert.getCriticalExtensionOIDs() != null)
									{
										ci = cert.getCriticalExtensionOIDs().contains(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
									}

									PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
									if (RFC3280CertPathUtilities.ANY_POLICY.Equals(p_node.getValidPolicy()))
									{
										PKIXPolicyNode c_node = new PKIXPolicyNode(new ArrayList(), i, (Set)m_idp.get(id_p), p_node, pq, id_p, ci);
										p_node.addChild(c_node);
										policyNodes[i].add(c_node);
									}
									break;
								}
							}
						}

						//
						// (2)
						//
					}
					else if (policyMapping <= 0)
					{
						Iterator nodes_i = policyNodes[i].iterator();
						while (nodes_i.hasNext())
						{
							PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
							if (node.getValidPolicy().Equals(id_p))
							{
								PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
								p_node.removeChild(node);
								nodes_i.remove();
								for (int k = (i - 1); k >= 0; k--)
								{
									List nodes = policyNodes[k];
									for (int l = 0; l < nodes.size(); l++)
									{
										PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
										if (!node2.hasChildren())
										{
											_validPolicyTree = CertPathValidatorUtilities.removePolicyNode(_validPolicyTree, policyNodes, node2);
											if (_validPolicyTree == null)
											{
												break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return _validPolicyTree;
		}

		protected internal static void prepareNextCertA(CertPath certPath, int index)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			//
			// (a) check the policy mappings
			//
			ASN1Sequence pm = null;
			try
			{
				pm = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.POLICY_MAPPINGS));
			}
			catch (AnnotatedException ex)
			{
				throw new ExtCertPathValidatorException("Policy mappings extension could not be decoded.", ex, certPath, index);
			}
			if (pm != null)
			{
				ASN1Sequence mappings = pm;

				for (int j = 0; j < mappings.size(); j++)
				{
					ASN1ObjectIdentifier issuerDomainPolicy = null;
					ASN1ObjectIdentifier subjectDomainPolicy = null;
					try
					{
						ASN1Sequence mapping = DERSequence.getInstance(mappings.getObjectAt(j));

						issuerDomainPolicy = ASN1ObjectIdentifier.getInstance(mapping.getObjectAt(0));
						subjectDomainPolicy = ASN1ObjectIdentifier.getInstance(mapping.getObjectAt(1));
					}
					catch (Exception e)
					{
						throw new ExtCertPathValidatorException("Policy mappings extension contents could not be decoded.", e, certPath, index);
					}

					if (RFC3280CertPathUtilities.ANY_POLICY.Equals(issuerDomainPolicy.getId()))
					{

						throw new CertPathValidatorException("IssuerDomainPolicy is anyPolicy", null, certPath, index);
					}

					if (RFC3280CertPathUtilities.ANY_POLICY.Equals(subjectDomainPolicy.getId()))
					{

						throw new CertPathValidatorException("SubjectDomainPolicy is anyPolicy,", null, certPath, index);
					}
				}
			}
		}

		protected internal static void processCertF(CertPath certPath, int index, PKIXPolicyNode validPolicyTree, int explicitPolicy)
		{
			//
			// (f)
			//
			if (explicitPolicy <= 0 && validPolicyTree == null)
			{
				throw new ExtCertPathValidatorException("No valid policy tree found when one expected.", null, certPath, index);
			}
		}

		protected internal static PKIXPolicyNode processCertE(CertPath certPath, int index, PKIXPolicyNode validPolicyTree)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			// 
			// (e)
			//
			ASN1Sequence certPolicies = null;
			try
			{
				certPolicies = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.CERTIFICATE_POLICIES));
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathValidatorException("Could not read certificate policies extension from certificate.", e, certPath, index);
			}
			if (certPolicies == null)
			{
				validPolicyTree = null;
			}
			return validPolicyTree;
		}

		protected internal static void processCertBC(CertPath certPath, int index, PKIXNameConstraintValidator nameConstraintValidator)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			int n = certs.size();
			// i as defined in the algorithm description
			int i = n - index;
			//
			// (b), (c) permitted and excluded subtree checking.
			//
			if (!(CertPathValidatorUtilities.isSelfIssued(cert) && (i < n)))
			{
				X500Name principal = PrincipalUtils.getSubjectPrincipal(cert);
				ASN1Sequence dns;

				try
				{
					dns = DERSequence.getInstance(principal.getEncoded());
				}
				catch (Exception e)
				{
					throw new CertPathValidatorException("Exception extracting subject name when checking subtrees.", e, certPath, index);
				}

				try
				{
					nameConstraintValidator.checkPermittedDN(dns);
					nameConstraintValidator.checkExcludedDN(dns);
				}
				catch (PKIXNameConstraintValidatorException e)
				{
					throw new CertPathValidatorException("Subtree check for certificate subject failed.", e, certPath, index);
				}

				GeneralNames altName = null;
				try
				{
					altName = GeneralNames.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME));
				}
				catch (Exception e)
				{
					throw new CertPathValidatorException("Subject alternative name extension could not be decoded.", e, certPath, index);
				}
				RDN[] emails = X500Name.getInstance(dns).getRDNs(BCStyle.EmailAddress);
				for (int eI = 0; eI != emails.Length; eI++)
				{
					// TODO: this should take into account multi-valued RDNs
					string email = ((ASN1String)emails[eI].getFirst().getValue()).getString();
					GeneralName emailAsGeneralName = new GeneralName(GeneralName.rfc822Name, email);
					try
					{
						nameConstraintValidator.checkPermitted(emailAsGeneralName);
						nameConstraintValidator.checkExcluded(emailAsGeneralName);
					}
					catch (PKIXNameConstraintValidatorException ex)
					{
						throw new CertPathValidatorException("Subtree check for certificate subject alternative email failed.", ex, certPath, index);
					}
				}
				if (altName != null)
				{
					GeneralName[] genNames = null;
					try
					{
						genNames = altName.getNames();
					}
					catch (Exception e)
					{
						throw new CertPathValidatorException("Subject alternative name contents could not be decoded.", e, certPath, index);
					}
					for (int j = 0; j < genNames.Length; j++)
					{

						try
						{
							nameConstraintValidator.checkPermitted(genNames[j]);
							nameConstraintValidator.checkExcluded(genNames[j]);
						}
						catch (PKIXNameConstraintValidatorException e)
						{
							throw new CertPathValidatorException("Subtree check for certificate subject alternative name failed.", e, certPath, index);
						}
					}
				}
			}
		}

		protected internal static PKIXPolicyNode processCertD(CertPath certPath, int index, Set acceptablePolicies, PKIXPolicyNode validPolicyTree, List[] policyNodes, int inhibitAnyPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			int n = certs.size();
			// i as defined in the algorithm description
			int i = n - index;
			//
			// (d) policy Information checking against initial policy and
			// policy mapping
			//
			ASN1Sequence certPolicies = null;
			try
			{
				certPolicies = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.CERTIFICATE_POLICIES));
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathValidatorException("Could not read certificate policies extension from certificate.", e, certPath, index);
			}
			if (certPolicies != null && validPolicyTree != null)
			{
				//
				// (d) (1)
				//
				Enumeration e = certPolicies.getObjects();
				Set pols = new HashSet();

				while (e.hasMoreElements())
				{
					PolicyInformation pInfo = PolicyInformation.getInstance(e.nextElement());
					ASN1ObjectIdentifier pOid = pInfo.getPolicyIdentifier();

					pols.add(pOid.getId());

					if (!RFC3280CertPathUtilities.ANY_POLICY.Equals(pOid.getId()))
					{
						Set pq = null;
						try
						{
							pq = CertPathValidatorUtilities.getQualifierSet(pInfo.getPolicyQualifiers());
						}
						catch (CertPathValidatorException ex)
						{
							throw new ExtCertPathValidatorException("Policy qualifier info set could not be build.", ex, certPath, index);
						}

						bool match = CertPathValidatorUtilities.processCertD1i(i, policyNodes, pOid, pq);

						if (!match)
						{
							CertPathValidatorUtilities.processCertD1ii(i, policyNodes, pOid, pq);
						}
					}
				}

				if (acceptablePolicies.isEmpty() || acceptablePolicies.contains(RFC3280CertPathUtilities.ANY_POLICY))
				{
					acceptablePolicies.clear();
					acceptablePolicies.addAll(pols);
				}
				else
				{
					Iterator it = acceptablePolicies.iterator();
					Set t1 = new HashSet();

					while (it.hasNext())
					{
						object o = it.next();

						if (pols.contains(o))
						{
							t1.add(o);
						}
					}
					acceptablePolicies.clear();
					acceptablePolicies.addAll(t1);
				}

				//
				// (d) (2)
				//
				if ((inhibitAnyPolicy > 0) || ((i < n) && CertPathValidatorUtilities.isSelfIssued(cert)))
				{
					e = certPolicies.getObjects();

					while (e.hasMoreElements())
					{
						PolicyInformation pInfo = PolicyInformation.getInstance(e.nextElement());

						if (RFC3280CertPathUtilities.ANY_POLICY.Equals(pInfo.getPolicyIdentifier().getId()))
						{
							Set _apq = CertPathValidatorUtilities.getQualifierSet(pInfo.getPolicyQualifiers());
							List _nodes = policyNodes[i - 1];

							for (int k = 0; k < _nodes.size(); k++)
							{
								PKIXPolicyNode _node = (PKIXPolicyNode)_nodes.get(k);

								Iterator _policySetIter = _node.getExpectedPolicies().iterator();
								while (_policySetIter.hasNext())
								{
									object _tmp = _policySetIter.next();

									string _policy;
									if (_tmp is string)
									{
										_policy = (string)_tmp;
									}
									else if (_tmp is ASN1ObjectIdentifier)
									{
										_policy = ((ASN1ObjectIdentifier)_tmp).getId();
									}
									else
									{
										continue;
									}

									bool _found = false;
									Iterator _childrenIter = _node.getChildren();

									while (_childrenIter.hasNext())
									{
										PKIXPolicyNode _child = (PKIXPolicyNode)_childrenIter.next();

										if (_policy.Equals(_child.getValidPolicy()))
										{
											_found = true;
										}
									}

									if (!_found)
									{
										Set _newChildExpectedPolicies = new HashSet();
										_newChildExpectedPolicies.add(_policy);

										PKIXPolicyNode _newChild = new PKIXPolicyNode(new ArrayList(), i, _newChildExpectedPolicies, _node, _apq, _policy, false);
										_node.addChild(_newChild);
										policyNodes[i].add(_newChild);
									}
								}
							}
							break;
						}
					}
				}

				PKIXPolicyNode _validPolicyTree = validPolicyTree;
				//
				// (d) (3)
				//
				for (int j = (i - 1); j >= 0; j--)
				{
					List nodes = policyNodes[j];

					for (int k = 0; k < nodes.size(); k++)
					{
						PKIXPolicyNode node = (PKIXPolicyNode)nodes.get(k);
						if (!node.hasChildren())
						{
							_validPolicyTree = CertPathValidatorUtilities.removePolicyNode(_validPolicyTree, policyNodes, node);
							if (_validPolicyTree == null)
							{
								break;
							}
						}
					}
				}

				//
				// d (4)
				//
				Set criticalExtensionOids = cert.getCriticalExtensionOIDs();

				if (criticalExtensionOids != null)
				{
					bool critical = criticalExtensionOids.contains(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);

					List nodes = policyNodes[i];
					for (int j = 0; j < nodes.size(); j++)
					{
						PKIXPolicyNode node = (PKIXPolicyNode)nodes.get(j);
						node.setCritical(critical);
					}
				}
				return _validPolicyTree;
			}
			return null;
		}

		protected internal static void processCertA(CertPath certPath, PKIXExtendedParameters paramsPKIX, int index, PublicKey workingPublicKey, bool verificationAlreadyPerformed, X500Name workingIssuerName, X509Certificate sign, JcaJceHelper helper)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (a) verify
			//
			if (!verificationAlreadyPerformed)
			{
				try
				{
					// (a) (1)
					//
					CertPathValidatorUtilities.verifyX509Certificate(cert, workingPublicKey, paramsPKIX.getSigProvider());
				}
				catch (GeneralSecurityException e)
				{
					throw new ExtCertPathValidatorException("Could not validate certificate signature.", e, certPath, index);
				}
			}

			try
			{
				// (a) (2)
				//
				cert.checkValidity(CertPathValidatorUtilities.getValidCertDateFromValidityModel(paramsPKIX, certPath, index));
			}
			catch (CertificateExpiredException e)
			{
				throw new ExtCertPathValidatorException("Could not validate certificate: " + e.Message, e, certPath, index);
			}
			catch (CertificateNotYetValidException e)
			{
				throw new ExtCertPathValidatorException("Could not validate certificate: " + e.Message, e, certPath, index);
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathValidatorException("Could not validate time of certificate.", e, certPath, index);
			}

			//
			// (a) (3)
			//
			if (paramsPKIX.isRevocationEnabled())
			{
				try
				{
					checkCRLs(paramsPKIX, cert, CertPathValidatorUtilities.getValidCertDateFromValidityModel(paramsPKIX, certPath, index), sign, workingPublicKey, certs, helper);
				}
				catch (AnnotatedException e)
				{
					Exception cause = e;
					if (null != e.InnerException)
					{
						cause = e.InnerException;
					}
					throw new ExtCertPathValidatorException(e.Message, cause, certPath, index);
				}
			}

			//
			// (a) (4) name chaining
			//
			if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).Equals(workingIssuerName))
			{
				throw new ExtCertPathValidatorException("IssuerName(" + PrincipalUtils.getEncodedIssuerPrincipal(cert) + ") does not match SubjectName(" + workingIssuerName + ") of signing certificate.", null, certPath, index);
			}
		}

		protected internal static int prepareNextCertI1(CertPath certPath, int index, int explicitPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (i)
			//
			ASN1Sequence pc = null;
			try
			{
				pc = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.POLICY_CONSTRAINTS));
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Policy constraints extension cannot be decoded.", e, certPath, index);
			}

			int tmpInt;

			if (pc != null)
			{
				Enumeration policyConstraints = pc.getObjects();

				while (policyConstraints.hasMoreElements())
				{
					try
					{

						ASN1TaggedObject constraint = ASN1TaggedObject.getInstance(policyConstraints.nextElement());
						if (constraint.getTagNo() == 0)
						{
							tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
							if (tmpInt < explicitPolicy)
							{
								return tmpInt;
							}
							break;
						}
					}
					catch (IllegalArgumentException e)
					{
						throw new ExtCertPathValidatorException("Policy constraints extension contents cannot be decoded.", e, certPath, index);
					}
				}
			}
			return explicitPolicy;
		}

		protected internal static int prepareNextCertI2(CertPath certPath, int index, int policyMapping)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (i)
			//
			ASN1Sequence pc = null;
			try
			{
				pc = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.POLICY_CONSTRAINTS));
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Policy constraints extension cannot be decoded.", e, certPath, index);
			}

			int tmpInt;

			if (pc != null)
			{
				Enumeration policyConstraints = pc.getObjects();

				while (policyConstraints.hasMoreElements())
				{
					try
					{
						ASN1TaggedObject constraint = ASN1TaggedObject.getInstance(policyConstraints.nextElement());
						if (constraint.getTagNo() == 1)
						{
							tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
							if (tmpInt < policyMapping)
							{
								return tmpInt;
							}
							break;
						}
					}
					catch (IllegalArgumentException e)
					{
						throw new ExtCertPathValidatorException("Policy constraints extension contents cannot be decoded.", e, certPath, index);
					}
				}
			}
			return policyMapping;
		}

		protected internal static void prepareNextCertG(CertPath certPath, int index, PKIXNameConstraintValidator nameConstraintValidator)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (g) handle the name constraints extension
			//
			NameConstraints nc = null;
			try
			{
				ASN1Sequence ncSeq = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.NAME_CONSTRAINTS));
				if (ncSeq != null)
				{
					nc = NameConstraints.getInstance(ncSeq);
				}
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Name constraints extension could not be decoded.", e, certPath, index);
			}
			if (nc != null)
			{

				//
				// (g) (1) permitted subtrees
				//
				GeneralSubtree[] permitted = nc.getPermittedSubtrees();
				if (permitted != null)
				{
					try
					{
						nameConstraintValidator.intersectPermittedSubtree(permitted);
					}
					catch (Exception ex)
					{
						throw new ExtCertPathValidatorException("Permitted subtrees cannot be build from name constraints extension.", ex, certPath, index);
					}
				}

				//
				// (g) (2) excluded subtrees
				//
				GeneralSubtree[] excluded = nc.getExcludedSubtrees();
				if (excluded != null)
				{
					for (int i = 0; i != excluded.Length; i++)
					{
					try
					{
							nameConstraintValidator.addExcludedSubtree(excluded[i]);
					}
					catch (Exception ex)
					{
						throw new ExtCertPathValidatorException("Excluded subtrees cannot be build from name constraints extension.", ex, certPath, index);
					}
					}
				}
			}
		}

		/// <summary>
		/// Checks a distribution point for revocation information for the
		/// certificate <code>cert</code>.
		/// </summary>
		/// <param name="dp">                 The distribution point to consider. </param>
		/// <param name="paramsPKIX">         PKIX parameters. </param>
		/// <param name="cert">               Certificate to check if it is revoked. </param>
		/// <param name="validDate">          The date when the certificate revocation status should be
		///                           checked. </param>
		/// <param name="defaultCRLSignCert"> The issuer certificate of the certificate <code>cert</code>. </param>
		/// <param name="defaultCRLSignKey">  The public key of the issuer certificate
		///                           <code>defaultCRLSignCert</code>. </param>
		/// <param name="certStatus">         The current certificate revocation status. </param>
		/// <param name="reasonMask">         The reasons mask which is already checked. </param>
		/// <param name="certPathCerts">      The certificates of the certification path. </param>
		/// <exception cref="AnnotatedException"> if the certificate is revoked or the status cannot be checked
		///                            or some error occurs. </exception>
		private static void checkCRL(DistributionPoint dp, PKIXExtendedParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey, CertStatus certStatus, ReasonsMask reasonMask, List certPathCerts, JcaJceHelper helper)
		{
			DateTime currentDate = new DateTime(System.currentTimeMillis());
			if (validDate.Ticks > currentDate.Ticks)
			{
				throw new AnnotatedException("Validation time is in future.");
			}

			// (a)
			/*
			 * We always get timely valid CRLs, so there is no step (a) (1).
			 * "locally cached" CRLs are assumed to be in getStore(), additional
			 * CRLs must be enabled in the ExtendedPKIXParameters and are in
			 * getAdditionalStore()
			 */

			Set crls = CertPathValidatorUtilities.getCompleteCRLs(dp, cert, currentDate, paramsPKIX);
			bool validCrlFound = false;
			AnnotatedException lastException = null;
			Iterator crl_iter = crls.iterator();

			while (crl_iter.hasNext() && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonMask.isAllReasons())
			{
				try
				{
					X509CRL crl = (X509CRL)crl_iter.next();

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
					Set keys = RFC3280CertPathUtilities.processCRLF(crl, cert, defaultCRLSignCert, defaultCRLSignKey, paramsPKIX, certPathCerts, helper);
					// (g)
					PublicKey key = RFC3280CertPathUtilities.processCRLG(crl, keys);

					X509CRL deltaCRL = null;

					DateTime validityDate = currentDate;

					if (paramsPKIX.getDate() != null)
					{
						validityDate = paramsPKIX.getDate();
					}

					if (paramsPKIX.isUseDeltasEnabled())
					{
						// get delta CRLs
						Set deltaCRLs = CertPathValidatorUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
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
					 * the CRL validity time
					 */

					if (paramsPKIX.getValidityModel() != PKIXExtendedParameters.CHAIN_VALIDITY_MODEL)
					{
						/*
						 * if a certificate has expired, but was revoked, it is not
						 * more in the CRL, so it would be regarded as valid if the
						 * first check is not done
						 */
						if (cert.getNotAfter().getTime() < crl.getThisUpdate().getTime())
						{
							throw new AnnotatedException("No valid CRL for current time found.");
						}
					}

					RFC3280CertPathUtilities.processCRLB1(dp, cert, crl);

					// (b) (2)
					RFC3280CertPathUtilities.processCRLB2(dp, cert, crl);

					// (c)
					RFC3280CertPathUtilities.processCRLC(deltaCRL, crl, paramsPKIX);

					// (i)
					RFC3280CertPathUtilities.processCRLI(validDate, deltaCRL, cert, certStatus, paramsPKIX);

					// (j)
					RFC3280CertPathUtilities.processCRLJ(validDate, crl, cert, certStatus);

					// (k)
					if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
					{
						certStatus.setCertStatus(CertStatus.UNREVOKED);
					}

					// update reasons mask
					reasonMask.addReasons(interimReasonsMask);

					Set criticalExtensions = crl.getCriticalExtensionOIDs();
					if (criticalExtensions != null)
					{
						criticalExtensions = new HashSet(criticalExtensions);
						criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
						criticalExtensions.remove(Extension.deltaCRLIndicator.getId());

						if (!criticalExtensions.isEmpty())
						{
							throw new AnnotatedException("CRL contains unsupported critical extensions.");
						}
					}

					if (deltaCRL != null)
					{
						criticalExtensions = deltaCRL.getCriticalExtensionOIDs();
						if (criticalExtensions != null)
						{
							criticalExtensions = new HashSet(criticalExtensions);
							criticalExtensions.remove(Extension.issuingDistributionPoint.getId());
							criticalExtensions.remove(Extension.deltaCRLIndicator.getId());
							if (!criticalExtensions.isEmpty())
							{
								throw new AnnotatedException("Delta CRL contains unsupported critical extension.");
							}
						}
					}

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

		/// <summary>
		/// Checks a certificate if it is revoked.
		/// </summary>
		/// <param name="paramsPKIX">       PKIX parameters. </param>
		/// <param name="cert">             Certificate to check if it is revoked. </param>
		/// <param name="validDate">        The date when the certificate revocation status should be
		///                         checked. </param>
		/// <param name="sign">             The issuer certificate of the certificate <code>cert</code>. </param>
		/// <param name="workingPublicKey"> The public key of the issuer certificate <code>sign</code>. </param>
		/// <param name="certPathCerts">    The certificates of the certification path. </param>
		/// <exception cref="AnnotatedException"> if the certificate is revoked or the status cannot be checked
		///                            or some error occurs. </exception>
		protected internal static void checkCRLs(PKIXExtendedParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate sign, PublicKey workingPublicKey, List certPathCerts, JcaJceHelper helper)
		{
			AnnotatedException lastException = null;
			CRLDistPoint crldp = null;
			try
			{
				crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("CRL distribution point extension could not be read.", e);
			}

			PKIXExtendedParameters.Builder paramsBldr = new PKIXExtendedParameters.Builder(paramsPKIX);
			try
			{
				List extras = CertPathValidatorUtilities.getAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX.getNamedCRLStoreMap());
				for (Iterator it = extras.iterator(); it.hasNext();)
				{
					paramsBldr.addCRLStore((PKIXCRLStore)it.next());
				}
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("No additional CRL locations could be decoded from CRL distribution point extension.", e);
			}
			CertStatus certStatus = new CertStatus();
			ReasonsMask reasonsMask = new ReasonsMask();
			PKIXExtendedParameters finalParams = paramsBldr.build();

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
					throw new AnnotatedException("Distribution points could not be read.", e);
				}
				if (dps != null)
				{
					for (int i = 0; i < dps.Length && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons(); i++)
					{
						try
						{
							checkCRL(dps[i], finalParams, cert, validDate, sign, workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
							validCrlFound = true;
						}
						catch (AnnotatedException e)
						{
							lastException = e;
						}
					}
				}
			}

			/*
			 * If the revocation status has not been determined, repeat the process
			 * above with any available CRLs not specified in a distribution point
			 * but issued by the certificate issuer.
			 */

			if (certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons())
			{
				try
				{
					/*
					 * assume a DP with both the reasons and the cRLIssuer fields
					 * omitted and a distribution point name of the certificate
					 * issuer.
					 */
					ASN1Primitive issuer = null;
					try
					{
						issuer = (new ASN1InputStream(PrincipalUtils.getEncodedIssuerPrincipal(cert).getEncoded())).readObject();
					}
					catch (Exception e)
					{
						throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", e);
					}
					DistributionPoint dp = new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(GeneralName.directoryName, issuer))), null, null);
					PKIXExtendedParameters paramsPKIXClone = (PKIXExtendedParameters)paramsPKIX.clone();
					checkCRL(dp, paramsPKIXClone, cert, validDate, sign, workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
					validCrlFound = true;
				}
				catch (AnnotatedException e)
				{
					lastException = e;
				}
			}

			if (!validCrlFound)
			{
				if (lastException is AnnotatedException)
				{
					throw lastException;
				}

				throw new AnnotatedException("No valid CRL found.", lastException);
			}
			if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
			{
				SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
				df.setTimeZone(TimeZone.getTimeZone("UTC"));
				string message = "Certificate revocation after " + df.format(certStatus.getRevocationDate());
				message += ", reason: " + crlReasons[certStatus.getCertStatus()];
				throw new AnnotatedException(message);
			}
			if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == CertStatus.UNREVOKED)
			{
				certStatus.setCertStatus(CertStatus.UNDETERMINED);
			}
			if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
			{
				throw new AnnotatedException("Certificate status could not be determined.");
			}
		}

		protected internal static int prepareNextCertJ(CertPath certPath, int index, int inhibitAnyPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (j)
			//
			ASN1Integer iap = null;
			try
			{
				iap = ASN1Integer.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.INHIBIT_ANY_POLICY));
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Inhibit any-policy extension cannot be decoded.", e, certPath, index);
			}

			if (iap != null)
			{
				int _inhibitAnyPolicy = iap.getValue().intValue();

				if (_inhibitAnyPolicy < inhibitAnyPolicy)
				{
					return _inhibitAnyPolicy;
				}
			}
			return inhibitAnyPolicy;
		}

		protected internal static void prepareNextCertK(CertPath certPath, int index)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (k)
			//
			BasicConstraints bc = null;
			try
			{
				bc = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.BASIC_CONSTRAINTS));
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Basic constraints extension cannot be decoded.", e, certPath, index);
			}
			if (bc != null)
			{
				if (!(bc.isCA()))
				{
					throw new CertPathValidatorException("Not a CA certificate");
				}
			}
			else
			{
				throw new CertPathValidatorException("Intermediate certificate lacks BasicConstraints");
			}
		}

		protected internal static int prepareNextCertL(CertPath certPath, int index, int maxPathLength)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (l)
			//
			if (!CertPathValidatorUtilities.isSelfIssued(cert))
			{
				if (maxPathLength <= 0)
				{
					throw new ExtCertPathValidatorException("Max path length not greater than zero", null, certPath, index);
				}

				return maxPathLength - 1;
			}
			return maxPathLength;
		}

		protected internal static int prepareNextCertM(CertPath certPath, int index, int maxPathLength)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);

			//
			// (m)
			//
			BasicConstraints bc = null;
			try
			{
				bc = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.BASIC_CONSTRAINTS));
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Basic constraints extension cannot be decoded.", e, certPath, index);
			}
			if (bc != null)
			{
				BigInteger _pathLengthConstraint = bc.getPathLenConstraint();

				if (_pathLengthConstraint != null)
				{
					int _plc = _pathLengthConstraint.intValue();

					if (_plc < maxPathLength)
					{
						return _plc;
					}
				}
			}
			return maxPathLength;
		}

		protected internal static void prepareNextCertN(CertPath certPath, int index)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);

			//
			// (n)
			//
			bool[] _usage = cert.getKeyUsage();

			if ((_usage != null) && !_usage[RFC3280CertPathUtilities.KEY_CERT_SIGN])
			{
				throw new ExtCertPathValidatorException("Issuer certificate keyusage extension is critical and does not permit key signing.", null, certPath, index);
			}
		}

		protected internal static void prepareNextCertO(CertPath certPath, int index, Set criticalExtensions, List pathCheckers)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (o)
			//

			Iterator tmpIter;
			tmpIter = pathCheckers.iterator();
			while (tmpIter.hasNext())
			{
				try
				{
					((PKIXCertPathChecker)tmpIter.next()).check(cert, criticalExtensions);
				}
				catch (CertPathValidatorException e)
				{
					throw new CertPathValidatorException(e.Message, e.InnerException, certPath, index);
				}
			}
			if (!criticalExtensions.isEmpty())
			{
				throw new ExtCertPathValidatorException("Certificate has unsupported critical extension: " + criticalExtensions, null, certPath, index);
			}
		}

		protected internal static int prepareNextCertH1(CertPath certPath, int index, int explicitPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (h)
			//
			if (!CertPathValidatorUtilities.isSelfIssued(cert))
			{
				//
				// (1)
				//
				if (explicitPolicy != 0)
				{
					return explicitPolicy - 1;
				}
			}
			return explicitPolicy;
		}

		protected internal static int prepareNextCertH2(CertPath certPath, int index, int policyMapping)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (h)
			//
			if (!CertPathValidatorUtilities.isSelfIssued(cert))
			{
				//
				// (2)
				//
				if (policyMapping != 0)
				{
					return policyMapping - 1;
				}
			}
			return policyMapping;
		}

		protected internal static int prepareNextCertH3(CertPath certPath, int index, int inhibitAnyPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (h)
			//
			if (!CertPathValidatorUtilities.isSelfIssued(cert))
			{
				//
				// (3)
				//
				if (inhibitAnyPolicy != 0)
				{
					return inhibitAnyPolicy - 1;
				}
			}
			return inhibitAnyPolicy;
		}

		protected internal static readonly string[] crlReasons = new string[] {"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};

		protected internal static int wrapupCertA(int explicitPolicy, X509Certificate cert)
		{
			//
			// (a)
			//
			if (!CertPathValidatorUtilities.isSelfIssued(cert) && (explicitPolicy != 0))
			{
				explicitPolicy--;
			}
			return explicitPolicy;
		}

		protected internal static int wrapupCertB(CertPath certPath, int index, int explicitPolicy)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			//
			// (b)
			//
			int tmpInt;
			ASN1Sequence pc = null;
			try
			{
				pc = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(cert, RFC3280CertPathUtilities.POLICY_CONSTRAINTS));
			}
			catch (AnnotatedException e)
			{
				throw new ExtCertPathValidatorException("Policy constraints could not be decoded.", e, certPath, index);
			}
			if (pc != null)
			{
				Enumeration policyConstraints = pc.getObjects();

				while (policyConstraints.hasMoreElements())
				{
					ASN1TaggedObject constraint = (ASN1TaggedObject)policyConstraints.nextElement();
					switch (constraint.getTagNo())
					{
						case 0:
							try
							{
								tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
							}
							catch (Exception e)
							{
								throw new ExtCertPathValidatorException("Policy constraints requireExplicitPolicy field could not be decoded.", e, certPath, index);
							}
							if (tmpInt == 0)
							{
								return 0;
							}
							break;
					}
				}
			}
			return explicitPolicy;
		}

		protected internal static void wrapupCertF(CertPath certPath, int index, List pathCheckers, Set criticalExtensions)
		{
			List certs = certPath.getCertificates();
			X509Certificate cert = (X509Certificate)certs.get(index);
			Iterator tmpIter;
			tmpIter = pathCheckers.iterator();
			while (tmpIter.hasNext())
			{
				try
				{
					((PKIXCertPathChecker)tmpIter.next()).check(cert, criticalExtensions);
				}
				catch (CertPathValidatorException e)
				{
					throw new ExtCertPathValidatorException(e.Message, e, certPath, index);
				}
				catch (Exception e)
				{
					throw new CertPathValidatorException("Additional certificate path checker failed.", e, certPath, index);
				}
			}

			if (!criticalExtensions.isEmpty())
			{
				throw new ExtCertPathValidatorException("Certificate has unsupported critical extension: " + criticalExtensions, null, certPath, index);
			}
		}

		protected internal static PKIXPolicyNode wrapupCertG(CertPath certPath, PKIXExtendedParameters paramsPKIX, Set userInitialPolicySet, int index, List[] policyNodes, PKIXPolicyNode validPolicyTree, Set acceptablePolicies)
		{
			int n = certPath.getCertificates().size();
			//
			// (g)
			//
			PKIXPolicyNode intersection;

			//
			// (g) (i)
			//
			if (validPolicyTree == null)
			{
				if (paramsPKIX.isExplicitPolicyRequired())
				{
					throw new ExtCertPathValidatorException("Explicit policy requested but none available.", null, certPath, index);
				}
				intersection = null;
			}
			else if (CertPathValidatorUtilities.isAnyPolicy(userInitialPolicySet)) // (g)
			{
			// (ii)
				if (paramsPKIX.isExplicitPolicyRequired())
				{
					if (acceptablePolicies.isEmpty())
					{
						throw new ExtCertPathValidatorException("Explicit policy requested but none available.", null, certPath, index);
					}
					else
					{
						Set _validPolicyNodeSet = new HashSet();

						for (int j = 0; j < policyNodes.Length; j++)
						{
							List _nodeDepth = policyNodes[j];

							for (int k = 0; k < _nodeDepth.size(); k++)
							{
								PKIXPolicyNode _node = (PKIXPolicyNode)_nodeDepth.get(k);

								if (RFC3280CertPathUtilities.ANY_POLICY.Equals(_node.getValidPolicy()))
								{
									Iterator _iter = _node.getChildren();
									while (_iter.hasNext())
									{
										_validPolicyNodeSet.add(_iter.next());
									}
								}
							}
						}

						Iterator _vpnsIter = _validPolicyNodeSet.iterator();
						while (_vpnsIter.hasNext())
						{
							PKIXPolicyNode _node = (PKIXPolicyNode)_vpnsIter.next();
							string _validPolicy = _node.getValidPolicy();

							if (!acceptablePolicies.contains(_validPolicy))
							{
								// validPolicyTree =
								// removePolicyNode(validPolicyTree, policyNodes,
								// _node);
							}
						}
						if (validPolicyTree != null)
						{
							for (int j = (n - 1); j >= 0; j--)
							{
								List nodes = policyNodes[j];

								for (int k = 0; k < nodes.size(); k++)
								{
									PKIXPolicyNode node = (PKIXPolicyNode)nodes.get(k);
									if (!node.hasChildren())
									{
										validPolicyTree = CertPathValidatorUtilities.removePolicyNode(validPolicyTree, policyNodes, node);
									}
								}
							}
						}
					}
				}

				intersection = validPolicyTree;
			}
			else
			{
				//
				// (g) (iii)
				//
				// This implementation is not exactly same as the one described in
				// RFC3280.
				// However, as far as the validation result is concerned, both
				// produce
				// adequate result. The only difference is whether AnyPolicy is
				// remain
				// in the policy tree or not.
				//
				// (g) (iii) 1
				//
				Set _validPolicyNodeSet = new HashSet();

				for (int j = 0; j < policyNodes.Length; j++)
				{
					List _nodeDepth = policyNodes[j];

					for (int k = 0; k < _nodeDepth.size(); k++)
					{
						PKIXPolicyNode _node = (PKIXPolicyNode)_nodeDepth.get(k);

						if (RFC3280CertPathUtilities.ANY_POLICY.Equals(_node.getValidPolicy()))
						{
							Iterator _iter = _node.getChildren();
							while (_iter.hasNext())
							{
								PKIXPolicyNode _c_node = (PKIXPolicyNode)_iter.next();
								if (!RFC3280CertPathUtilities.ANY_POLICY.Equals(_c_node.getValidPolicy()))
								{
									_validPolicyNodeSet.add(_c_node);
								}
							}
						}
					}
				}

				//
				// (g) (iii) 2
				//
				Iterator _vpnsIter = _validPolicyNodeSet.iterator();
				while (_vpnsIter.hasNext())
				{
					PKIXPolicyNode _node = (PKIXPolicyNode)_vpnsIter.next();
					string _validPolicy = _node.getValidPolicy();

					if (!userInitialPolicySet.contains(_validPolicy))
					{
						validPolicyTree = CertPathValidatorUtilities.removePolicyNode(validPolicyTree, policyNodes, _node);
					}
				}

				//
				// (g) (iii) 4
				//
				if (validPolicyTree != null)
				{
					for (int j = (n - 1); j >= 0; j--)
					{
						List nodes = policyNodes[j];

						for (int k = 0; k < nodes.size(); k++)
						{
							PKIXPolicyNode node = (PKIXPolicyNode)nodes.get(k);
							if (!node.hasChildren())
							{
								validPolicyTree = CertPathValidatorUtilities.removePolicyNode(validPolicyTree, policyNodes, node);
							}
						}
					}
				}

				intersection = validPolicyTree;
			}
			return intersection;
		}

	}

}