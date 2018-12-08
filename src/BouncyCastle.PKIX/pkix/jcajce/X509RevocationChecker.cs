using System;

namespace org.bouncycastle.pkix.jcajce
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using PKIXCRLStore = org.bouncycastle.jcajce.PKIXCRLStore;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Iterable = org.bouncycastle.util.Iterable;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// X.509 Certificate Revocation Checker - still lacks OCSP support and support for delta CRLs.
	/// </summary>
	public class X509RevocationChecker : PKIXCertPathChecker
	{
		/// <summary>
		/// This is the default PKIX validity model. Actually there are two variants
		/// of this: The PKIX model and the modified PKIX model. The PKIX model
		/// verifies that all involved certificates must have been valid at the
		/// current time. The modified PKIX model verifies that all involved
		/// certificates were valid at the signing time. Both are indirectly choosen
		/// with the <seealso cref="PKIXParameters#setDate(Date)"/> method, so this
		/// methods sets the Date when <em>all</em> certificates must have been
		/// valid.
		/// </summary>
		public const int PKIX_VALIDITY_MODEL = 0;

		/// <summary>
		/// This model uses the following validity model. Each certificate must have
		/// been valid at the moment where is was used. That means the end
		/// certificate must have been valid at the time the signature was done. The
		/// CA certificate which signed the end certificate must have been valid,
		/// when the end certificate was signed. The CA (or Root CA) certificate must
		/// have been valid, when the CA certificate was signed and so on. So the
		/// <seealso cref="PKIXParameters#setDate(Date)"/> method sets the time, when
		/// the <em>end certificate</em> must have been valid. It is used e.g.
		/// in the German signature law.
		/// </summary>
		public const int CHAIN_VALIDITY_MODEL = 1;

		public class Builder
		{
			internal Set<TrustAnchor> trustAnchors;
			internal List<CertStore> crlCertStores = new ArrayList<CertStore>();
			internal List<Store<CRL>> crls = new ArrayList<Store<CRL>>();
			internal bool isCheckEEOnly;
			internal int validityModel = PKIX_VALIDITY_MODEL;
			internal Provider provider;
			internal string providerName;
			internal bool canSoftFail;
			internal long failLogMaxTime;
			internal long failHardMaxTime;

			/// <summary>
			/// Base constructor.
			/// </summary>
			/// <param name="trustAnchor"> the trust anchor our chain should start with. </param>
			public Builder(TrustAnchor trustAnchor)
			{
				this.trustAnchors = Collections.singleton(trustAnchor);
			}

			/// <summary>
			/// Base constructor.
			/// </summary>
			/// <param name="trustAnchors"> a set of potential trust anchors </param>
			public Builder(Set<TrustAnchor> trustAnchors)
			{
				this.trustAnchors = new HashSet<TrustAnchor>(trustAnchors);
			}

			/// <summary>
			/// Base constructor.
			/// </summary>
			/// <param name="trustStore"> a keystore of potential trust anchors </param>
			public Builder(KeyStore trustStore)
			{
				this.trustAnchors = new HashSet<TrustAnchor>();

				for (Enumeration en = trustStore.aliases(); en.hasMoreElements();)
				{
					string alias = (string)en.nextElement();

					if (trustStore.isCertificateEntry(alias))
					{
						trustAnchors.add(new TrustAnchor((X509Certificate)trustStore.getCertificate(alias), null));
					}
				}
			}

			/// <summary>
			/// Add a collection of CRLs to the checker.
			/// </summary>
			/// <param name="crls"> CRLs to be examined. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder addCrls(CertStore crls)
			{
				this.crlCertStores.add(crls);

				return this;
			}

			/// <summary>
			/// Add a collection of CRLs to the checker.
			/// </summary>
			/// <param name="crls"> CRLs to be examined. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder addCrls(Store<CRL> crls)
			{
				this.crls.add(crls);

				return this;
			}

			/// <param name="isTrue"> true if only end-entities should be checked, false otherwise. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setCheckEndEntityOnly(bool isTrue)
			{
				this.isCheckEEOnly = isTrue;

				return this;
			}

			/// <summary>
			/// Configure soft failure if CRLs/OCSP not available. If maxTime is greater than zero
			/// it represents the acceptable downtime for any responders or distribution points we
			/// are trying to connect to, with downtime measured from the first failure. Initially
			/// failures will log at Level.WARNING, once maxTime is exceeded any failures will be
			/// logged as Level.SEVERE. Setting maxTime to zero will mean 1 failure will be allowed
			/// before failures are logged as severe.
			/// </summary>
			/// <param name="isTrue"> true soft failure should be enabled, false otherwise. </param>
			/// <param name="maxTime"> the time that can pass between the first failure and the most recent. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setSoftFail(bool isTrue, long maxTime)
			{
				this.canSoftFail = isTrue;
				this.failLogMaxTime = maxTime;
				this.failHardMaxTime = -1;

				return this;
			}

			/// <summary>
			/// Configure soft failure with a hard limit if CRLs/OCSP not available. If maxTime is
			/// greater than zero it represents the acceptable downtime for any responders or
			/// distribution points we are trying to connect to, with downtime measured from the
			/// first failure. Initially failures will log at Level.WARNING, once 75% of maxTime is exceeded
			/// any failures will be logged as Level.SEVERE. At maxTime any failures will be treated as hard,
			/// setting maxTime to zero will mean 1 failure will be allowed.
			/// </summary>
			/// <param name="isTrue"> true soft failure should be enabled, false otherwise. </param>
			/// <param name="maxTime"> the time that can pass between the first failure and the most recent. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder setSoftFailHardLimit(bool isTrue, long maxTime)
			{
				this.canSoftFail = isTrue;
				this.failLogMaxTime = (maxTime * 3) / 4;
				this.failHardMaxTime = maxTime;

				return this;
			}

			/// <summary>
			/// Configure to use the installed provider with name ProviderName.
			/// </summary>
			/// <param name="provider"> provider to use. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder usingProvider(Provider provider)
			{
				this.provider = provider;

				return this;
			}

			/// <summary>
			/// Configure to use the installed provider with name ProviderName.
			/// </summary>
			/// <param name="providerName"> name of the installed provider to use. </param>
			/// <returns> the current builder instance. </returns>
			public virtual Builder usingProvider(string providerName)
			{
				this.providerName = providerName;

				return this;
			}

			/// <summary>
			/// Build a revocation checker conforming to the current builder.
			/// </summary>
			/// <returns> a new X509RevocationChecker. </returns>
			public virtual X509RevocationChecker build()
			{
				return new X509RevocationChecker(this);
			}
		}

		private static Logger LOG = Logger.getLogger(typeof(X509RevocationChecker).getName());

		private readonly Map<X500Principal, long> failures = new HashMap<X500Principal, long>();
		private readonly Map<GeneralName, WeakReference<X509CRL>> crlCache = new WeakHashMap<GeneralName, WeakReference<X509CRL>>();
		private readonly Set<TrustAnchor> trustAnchors;
		private readonly bool isCheckEEOnly;
		private readonly List<Store<CRL>> crls;
		private readonly List<CertStore> crlCertStores;
		private readonly PKIXJcaJceHelper helper;
		private readonly bool canSoftFail;
		private readonly long failLogMaxTime;
		private readonly long failHardMaxTime;

		private X500Principal workingIssuerName;
		private PublicKey workingPublicKey;
		private X509Certificate signingCert;

		private X509RevocationChecker(Builder bldr)
		{
			this.crls = new ArrayList<Store<CRL>>(bldr.crls);
			this.crlCertStores = new ArrayList<CertStore>(bldr.crlCertStores);
			this.isCheckEEOnly = bldr.isCheckEEOnly;
			this.trustAnchors = bldr.trustAnchors;
			this.canSoftFail = bldr.canSoftFail;
			this.failLogMaxTime = bldr.failLogMaxTime;
			this.failHardMaxTime = bldr.failHardMaxTime;

			if (bldr.provider != null)
			{
				this.helper = new PKIXProviderJcaJceHelper(bldr.provider);
			}
			else if (!string.ReferenceEquals(bldr.providerName, null))
			{
				helper = new PKIXNamedJcaJceHelper(bldr.providerName);
			}
			else
			{
				helper = new PKIXDefaultJcaJceHelper();
			}
		}

		public virtual void init(bool forward)
		{
			if (forward)
			{
				throw new IllegalArgumentException("forward processing not supported");
			}
			this.workingIssuerName = null;
		}

		public virtual bool isForwardCheckingSupported()
		{
			return false;
		}

		public virtual Set<string> getSupportedExtensions()
		{
			return null;
		}

		public virtual void check(Certificate certificate, Collection<string> collection)
		{
			X509Certificate cert = (X509Certificate)certificate;

			if (isCheckEEOnly && cert.getBasicConstraints() != -1)
			{
				this.workingIssuerName = cert.getSubjectX500Principal();
				this.workingPublicKey = cert.getPublicKey();
				this.signingCert = cert;

				return;
			}

			TrustAnchor trustAnchor = null;

			if (workingIssuerName == null)
			{
				this.workingIssuerName = cert.getIssuerX500Principal();

				for (Iterator it = trustAnchors.iterator(); it.hasNext();)
				{
					TrustAnchor anchor = (TrustAnchor)it.next();

					if (workingIssuerName.Equals(anchor.getCA()) || workingIssuerName.Equals(anchor.getTrustedCert().getSubjectX500Principal()))
					{
						trustAnchor = anchor;
					}
				}

				if (trustAnchor == null)
				{
					throw new CertPathValidatorException("no trust anchor found for " + workingIssuerName);
				}

				this.signingCert = trustAnchor.getTrustedCert();
				this.workingPublicKey = signingCert.getPublicKey();
			}

			PKIXParameters baseParams;
			List<X500Principal> issuerList = new ArrayList<X500Principal>();

			try
			{
				baseParams = new PKIXParameters(trustAnchors);

				baseParams.setRevocationEnabled(false);
				baseParams.setDate(DateTime.Now);

				for (int i = 0; i != crlCertStores.size(); i++)
				{
					if (LOG.isLoggable(Level.FINE))
					{
						addIssuers(issuerList, crlCertStores.get(i));
					}
					baseParams.addCertStore(crlCertStores.get(i));
				}
			}
			catch (GeneralSecurityException e)
			{
				throw new RuntimeException("error setting up baseParams: " + e.Message);
			}

			PKIXExtendedParameters.Builder pkixParamsBldr = new PKIXExtendedParameters.Builder(baseParams);

			for (int i = 0; i != crls.size(); i++)
			{
				if (LOG.isLoggable(Level.FINE))
				{
					addIssuers(issuerList, crls.get(i));
				}
				pkixParamsBldr.addCRLStore(new LocalCRLStore(this, crls.get(i)));
			}

			if (issuerList.isEmpty())
			{
				LOG.log(Level.INFO, "configured with 0 pre-loaded CRLs");
			}
			else
			{
				if (LOG.isLoggable(Level.FINE))
				{
					for (int i = 0; i != issuerList.size(); i++)
					{
						LOG.log(Level.INFO, @"configuring with CRL for issuer """ + issuerList.get(i) + @"""");
					}
				}
			}

			try
			{
				checkCRLs(pkixParamsBldr.build(), cert, DateTime.Now, signingCert, workingPublicKey, new ArrayList(), helper);
			}
			catch (AnnotatedException e)
			{
				throw new CertPathValidatorException(e.Message, e.InnerException);
			}
			catch (CRLNotFoundException e)
			{
				if (cert.getExtensionValue(Extension.cRLDistributionPoints.getId()) != null)
				{
					CRL crl = null;
					try
					{
						crl = downloadCRLs(cert.getIssuerX500Principal(), baseParams.getDate(), RevocationUtilities.getExtensionValue(cert, Extension.cRLDistributionPoints), helper);
					}
					catch (AnnotatedException)
					{
						throw new CertPathValidatorException(e.Message, e.InnerException);
					}

					if (crl != null)
					{
						try
						{
							pkixParamsBldr.addCRLStore(new LocalCRLStore(this, new CollectionStore<CRL>(Collections.singleton(crl))));
							checkCRLs(pkixParamsBldr.build(), cert, DateTime.Now, signingCert, workingPublicKey, new ArrayList(), helper);
						}
						catch (AnnotatedException)
						{
							throw new CertPathValidatorException(e.Message, e.InnerException);
						}
					}
					else
					{
						if (canSoftFail)
						{
							X500Principal issuer = cert.getIssuerX500Principal();

							long? initial = failures.get(issuer);
							if (initial != null)
							{
								 long period = System.currentTimeMillis() - initial.Value;
								 if (failHardMaxTime != -1 && failHardMaxTime < period)
								 {
									 throw e;
								 }
								 if (period < failLogMaxTime)
								 {
									 LOG.log(Level.WARNING, @"soft failing for issuer: """ + issuer + @"""");
								 }
								 else
								 {
									 LOG.log(Level.SEVERE, @"soft failing for issuer: """ + issuer + @"""");
								 }
							}
							else
							{
								failures.put(issuer, System.currentTimeMillis());
							}
						}
						else
						{
							throw e;
						}
					}
				}
				else
				{
					throw e;
				}
			}

			this.signingCert = cert;
			this.workingPublicKey = cert.getPublicKey();
			this.workingIssuerName = cert.getSubjectX500Principal();
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private void addIssuers(final java.util.List<javax.security.auth.x500.X500Principal> issuerList, java.security.cert.CertStore certStore) throws java.security.cert.CertStoreException
		private void addIssuers(List<X500Principal> issuerList, CertStore certStore)
		{
			certStore.getCRLs(new X509CRLSelectorAnonymousInnerClass(this, issuerList));
		}

		public class X509CRLSelectorAnonymousInnerClass : X509CRLSelector
		{
			private readonly X509RevocationChecker outerInstance;

			private List<X500Principal> issuerList;

			public X509CRLSelectorAnonymousInnerClass(X509RevocationChecker outerInstance, List<X500Principal> issuerList)
			{
				this.outerInstance = outerInstance;
				this.issuerList = issuerList;
			}

			public bool match(CRL crl)
			{
				if (!(crl is X509CRL))
				{
					return false;
				}

				issuerList.add(((X509CRL)crl).getIssuerX500Principal());

				return false;
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private void addIssuers(final java.util.List<javax.security.auth.x500.X500Principal> issuerList, org.bouncycastle.util.Store<java.security.cert.CRL> certStore)
		private void addIssuers(List<X500Principal> issuerList, Store<CRL> certStore)
		{
			certStore.getMatches(new SelectorAnonymousInnerClass(this, issuerList));
		}

		public class SelectorAnonymousInnerClass : Selector<CRL>
		{
			private readonly X509RevocationChecker outerInstance;

			private List<X500Principal> issuerList;

			public SelectorAnonymousInnerClass(X509RevocationChecker outerInstance, List<X500Principal> issuerList)
			{
				this.outerInstance = outerInstance;
				this.issuerList = issuerList;
			}

			public bool match(CRL crl)
			{
				if (!(crl is X509CRL))
				{
					return false;
				}

				issuerList.add(((X509CRL)crl).getIssuerX500Principal());

				return false;
			}

			public object clone()
			{
				return this;
			}
		}

		private CRL downloadCRLs(X500Principal issuer, DateTime currentDate, ASN1Primitive crlDpPrimitive, JcaJceHelper helper)
		{
			CRLDistPoint crlDp = CRLDistPoint.getInstance(crlDpPrimitive);
			DistributionPoint[] points = crlDp.getDistributionPoints();

			for (int i = 0; i != points.Length; i++)
			{
				DistributionPoint dp = points[i];

				DistributionPointName dpn = dp.getDistributionPoint();
				if (dpn.getType() == DistributionPointName.FULL_NAME)
				{
					GeneralName[] names = GeneralNames.getInstance(dpn.getName()).getNames();

					for (int n = 0; n != names.Length; n++)
					{
						GeneralName name = names[n];
						if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
						{
							X509CRL crl;

							WeakReference<X509CRL> crlRef = crlCache.get(name);
							if (crlRef != null)
							{
								crl = crlRef.get();
								if (crl != null && !currentDate < crl.getThisUpdate() && !currentDate > crl.getNextUpdate())
								{
									return crl;
								}
								crlCache.remove(name); // delete expired/out-of-range entry
							}

							URL url = null;
							try
							{
								url = new URL(name.getName().ToString());

								CertificateFactory certFact = helper.createCertificateFactory("X.509");

								InputStream urlStream = url.openStream();

								crl = (X509CRL)certFact.generateCRL(new BufferedInputStream(urlStream));

								urlStream.close();

								LOG.log(Level.INFO, "downloaded CRL from CrlDP " + url + @" for issuer """ + issuer + @"""");

								crlCache.put(name, new WeakReference<X509CRL>(crl));

								return crl;
							}
							catch (Exception e)
							{
								if (LOG.isLoggable(Level.FINE))
								{
									LOG.log(Level.FINE, "CrlDP " + url + " ignored: " + e.Message, e);
								}
								else
								{
									LOG.log(Level.INFO, "CrlDP " + url + " ignored: " + e.Message);
								}
							}
						}
					}
				}
			}

			return null;
		}

		protected internal static readonly string[] crlReasons = new string[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};

		internal static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp, Map<GeneralName, PKIXCRLStore> namedCRLStoreMap)
		{
			if (crldp != null)
			{
				DistributionPoint[] dps = null;
				try
				{
					dps = crldp.getDistributionPoints();
				}
				catch (Exception e)
				{
					throw new AnnotatedException("could not read distribution points could not be read", e);
				}
				List<PKIXCRLStore> stores = new ArrayList<PKIXCRLStore>();

				for (int i = 0; i < dps.Length; i++)
				{
					DistributionPointName dpn = dps[i].getDistributionPoint();
					// look for URIs in fullName
					if (dpn != null)
					{
						if (dpn.getType() == DistributionPointName.FULL_NAME)
						{
							GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

							for (int j = 0; j < genNames.Length; j++)
							{
								PKIXCRLStore store = namedCRLStoreMap.get(genNames[j]);
								if (store != null)
								{
									stores.add(store);
								}
							}
						}
					}
				}

				return stores;
			}
			else
			{
				return Collections.EMPTY_LIST;
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
		/// or some error occurs. </exception>
		public virtual void checkCRLs(PKIXExtendedParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate sign, PublicKey workingPublicKey, List certPathCerts, PKIXJcaJceHelper helper)
		{
			AnnotatedException lastException = null;
			CRLDistPoint crldp = null;
			try
			{
				crldp = CRLDistPoint.getInstance(RevocationUtilities.getExtensionValue(cert, Extension.cRLDistributionPoints));
			}
			catch (Exception e)
			{
				throw new AnnotatedException("cannot read CRL distribution point extension", e);
			}

			PKIXExtendedParameters.Builder paramsBldr = new PKIXExtendedParameters.Builder(paramsPKIX);
			try
			{
				List extras = getAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX.getNamedCRLStoreMap());
				for (Iterator it = extras.iterator(); it.hasNext();)
				{
					paramsBldr.addCRLStore((PKIXCRLStore)it.next());
				}
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("no additional CRL locations could be decoded from CRL distribution point extension", e);
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
					throw new AnnotatedException("cannot read distribution points", e);
				}
				if (dps != null)
				{
					for (int i = 0; i < dps.Length && certStatus.getCertStatus() == CertStatus.UNREVOKED && !reasonsMask.isAllReasons(); i++)
					{
						try
						{
							RFC3280CertPathUtilities.checkCRL(dps[i], finalParams, cert, validDate, sign, workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
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
					X500Principal issuer = cert.getIssuerX500Principal();

					DistributionPoint dp = new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(GeneralName.directoryName, X500Name.getInstance(issuer.getEncoded())))), null, null);
					PKIXExtendedParameters paramsPKIXClone = (PKIXExtendedParameters)paramsPKIX.clone();
					RFC3280CertPathUtilities.checkCRL(dp, paramsPKIXClone, cert, validDate, sign, workingPublicKey, certStatus, reasonsMask, certPathCerts, helper);
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
					throw new CRLNotFoundException("no valid CRL found", lastException);
				}

				throw new CRLNotFoundException("no valid CRL found");
			}
			if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
			{
				SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
				df.setTimeZone(TimeZone.getTimeZone("UTC"));
				string message = @"certificate [issuer=""" + cert.getIssuerX500Principal() + @""",serialNumber="
											   + cert.getSerialNumber() + @",subject=""" + cert.getSubjectX500Principal() + @"""] revoked after " + df.format(certStatus.getRevocationDate());
				message += ", reason: " + crlReasons[certStatus.getCertStatus()];
				throw new AnnotatedException(message);
			}
			if (!reasonsMask.isAllReasons() && certStatus.getCertStatus() == CertStatus.UNREVOKED)
			{
				certStatus.setCertStatus(CertStatus.UNDETERMINED);
			}
			if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
			{
				throw new AnnotatedException("certificate status could not be determined");
			}
		}

		public virtual object clone()
		{
			return this;
		}

		public class LocalCRLStore<T> : PKIXCRLStore, Iterable<CRL> where T : java.security.cert.CRL
		{
			private readonly X509RevocationChecker outerInstance;

			internal Collection<CRL> _local;

			/// <summary>
			/// Basic constructor.
			/// </summary>
			/// <param name="collection"> - initial contents for the store, this is copied. </param>
			public LocalCRLStore(X509RevocationChecker outerInstance, Store<CRL> collection)
			{
				this.outerInstance = outerInstance;
				_local = new ArrayList<CRL>(collection.getMatches(null));
			}

			/// <summary>
			/// Return the matches in the collection for the passed in selector.
			/// </summary>
			/// <param name="selector"> the selector to match against. </param>
			/// <returns> a possibly empty collection of matching objects. </returns>
			public virtual Collection getMatches(Selector selector)
			{
				if (selector == null)
				{
					return new ArrayList<CRL>(_local);
				}
				else
				{
					List<CRL> col = new ArrayList<CRL>();
					Iterator<CRL> iter = _local.iterator();

					while (iter.hasNext())
					{
						CRL obj = iter.next();

						if (selector.match(obj))
						{
							col.add(obj);
						}
					}

					return col;
				}
			}

			public virtual Iterator<CRL> iterator()
			{
				return getMatches(null).iterator();
			}
		}
	}

}