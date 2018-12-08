using System;

namespace org.bouncycastle.pkix.jcajce
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using PKIXCRLStoreSelector = org.bouncycastle.jcajce.PKIXCRLStoreSelector;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedBuilderParameters = org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
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
				idp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(crl, Extension.issuingDistributionPoint));
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
							Enumeration e = ASN1Sequence.getInstance(crl.getIssuerX500Principal().getEncoded()).getObjects();
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
									genNames[0] = new GeneralName(X500Name.getInstance(((X509Certificate)cert).getIssuerX500Principal().getEncoded()));
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
					bc = BasicConstraints.getInstance(RevocationUtilities.getExtensionValue((X509Extension)cert, Extension.basicConstraints));
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
			ASN1Primitive idp = RevocationUtilities.getExtensionValue(crl, Extension.issuingDistributionPoint);
			bool isIndirect = false;
			if (idp != null)
			{
				if (IssuingDistributionPoint.getInstance(idp).isIndirectCRL())
				{
					isIndirect = true;
				}
			}
			byte[] issuerBytes;

				issuerBytes = crl.getIssuerX500Principal().getEncoded();


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
				if (crl.getIssuerX500Principal().Equals(((X509Certificate)cert).getIssuerX500Principal()))
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
				idp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(crl, Extension.issuingDistributionPoint));
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


		public static readonly string ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();

		public static readonly string FRESHEST_CRL = Extension.freshestCRL.getId();

		public static readonly string DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();

		public static readonly string BASIC_CONSTRAINTS = Extension.basicConstraints.getId();

		public static readonly string AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();

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
		protected internal static Set processCRLF(X509CRL crl, object cert, X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey, PKIXExtendedParameters paramsPKIX, List certPathCerts, PKIXJcaJceHelper helper)
		{
			// (f)

			// get issuer from CRL
			X509CertSelector certSelector = new X509CertSelector();
			try
			{
				byte[] issuerPrincipal = crl.getIssuerX500Principal().getEncoded();
				certSelector.setSubject(issuerPrincipal);
			}
			catch (IOException e)
			{
				throw new AnnotatedException("subject criteria for certificate selector to find issuer certificate for CRL could not be set", e);
			}

			PKIXCertStoreSelector selector = (new PKIXCertStoreSelector.Builder(certSelector)).build();

			// get CRL signing certs
			Collection coll;
			try
			{
				coll = RevocationUtilities.findCertificates(selector, paramsPKIX.getCertificateStores());
				coll.addAll(RevocationUtilities.findCertificates(selector, paramsPKIX.getCertStores()));
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
					CertPathBuilder builder = helper.createCertPathBuilder("PKIX");
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

					List certs = builder.build(extParams).getCertPath().getCertificates();
					validCerts.add(signingCert);
					validKeys.add(RevocationUtilities.getNextWorkingKey(certs, 0, helper));
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
					freshestCRL = CRLDistPoint.getInstance(RevocationUtilities.getExtensionValue(cert, Extension.freshestCRL));
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Freshest CRL extension could not be decoded from certificate.", e);
				}
				if (freshestCRL == null)
				{
					try
					{
						freshestCRL = CRLDistPoint.getInstance(RevocationUtilities.getExtensionValue(crl, Extension.freshestCRL));
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
						crlStores.addAll(RevocationUtilities.getAdditionalStoresFromCRLDistributionPoint(freshestCRL, paramsPKIX.getNamedCRLStoreMap()));
					}
					catch (AnnotatedException e)
					{
						throw new AnnotatedException("No new delta CRL locations could be added from Freshest CRL extension.", e);
					}

					// get delta CRL(s)
					try
					{
						set.addAll(RevocationUtilities.getDeltaCRLs(currentDate, crl, paramsPKIX.getCertStores(), crlStores));
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
				crlselect.addIssuerName(crl.getIssuerX500Principal().getEncoded());
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
					deltaSet.addAll(RevocationUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores()));
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
				completeidp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(completeCRL, Extension.issuingDistributionPoint));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("issuing distribution point extension could not be decoded.", e);
			}

			if (pkixParams.isUseDeltasEnabled())
			{
				// (c) (1)
				if (!deltaCRL.getIssuerX500Principal().Equals(completeCRL.getIssuerX500Principal()))
				{
					throw new AnnotatedException("complete CRL issuer does not match delta CRL issuer");
				}

				// (c) (2)
				IssuingDistributionPoint deltaidp = null;
				try
				{
					deltaidp = IssuingDistributionPoint.getInstance(RevocationUtilities.getExtensionValue(deltaCRL, Extension.issuingDistributionPoint));
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
					completeKeyIdentifier = RevocationUtilities.getExtensionValue(completeCRL, Extension.authorityKeyIdentifier);
				}
				catch (AnnotatedException e)
				{
					throw new AnnotatedException("Authority key identifier extension could not be extracted from complete CRL.", e);
				}

				ASN1Primitive deltaKeyIdentifier = null;
				try
				{
					deltaKeyIdentifier = RevocationUtilities.getExtensionValue(deltaCRL, Extension.authorityKeyIdentifier);
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
				RevocationUtilities.getCertStatus(validDate, deltacrl, cert, certStatus);
			}
		}

		protected internal static void processCRLJ(DateTime validDate, X509CRL completecrl, object cert, CertStatus certStatus)
		{
			if (certStatus.getCertStatus() == CertStatus.UNREVOKED)
			{
				RevocationUtilities.getCertStatus(validDate, completecrl, cert, certStatus);
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
		internal static void checkCRL(DistributionPoint dp, PKIXExtendedParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey, CertStatus certStatus, ReasonsMask reasonMask, List certPathCerts, PKIXJcaJceHelper helper)
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

			DateTime validityDate = currentDate;

			if (paramsPKIX.getDate() != null)
			{
				validityDate = paramsPKIX.getDate();
			}

			Set crls = RevocationUtilities.getCompleteCRLs(dp, cert, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
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

					if (paramsPKIX.isUseDeltasEnabled())
					{
						// get delta CRLs
						Set deltaCRLs = RevocationUtilities.getDeltaCRLs(validityDate, crl, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());
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
	}

}