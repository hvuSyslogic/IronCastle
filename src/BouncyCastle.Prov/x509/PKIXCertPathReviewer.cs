using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Enumerated = org.bouncycastle.asn1.ASN1Enumerated;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using AccessDescription = org.bouncycastle.asn1.x509.AccessDescription;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using GeneralSubtree = org.bouncycastle.asn1.x509.GeneralSubtree;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using NameConstraints = org.bouncycastle.asn1.x509.NameConstraints;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using Iso4217CurrencyCode = org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
	using MonetaryValue = org.bouncycastle.asn1.x509.qualified.MonetaryValue;
	using QCStatement = org.bouncycastle.asn1.x509.qualified.QCStatement;
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using LocaleString = org.bouncycastle.i18n.LocaleString;
	using TrustedInput = org.bouncycastle.i18n.filter.TrustedInput;
	using UntrustedInput = org.bouncycastle.i18n.filter.UntrustedInput;
	using UntrustedUrlInput = org.bouncycastle.i18n.filter.UntrustedUrlInput;
	using AnnotatedException = org.bouncycastle.jce.provider.AnnotatedException;
	using PKIXNameConstraintValidator = org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
	using PKIXNameConstraintValidatorException = org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
	using PKIXPolicyNode = org.bouncycastle.jce.provider.PKIXPolicyNode;
	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// PKIXCertPathReviewer<br>
	/// Validation of X.509 Certificate Paths. Tries to find as much errors in the Path as possible.
	/// </summary>
	public class PKIXCertPathReviewer : CertPathValidatorUtilities
	{

		private static readonly string QC_STATEMENT = Extension.qCStatements.getId();
		private static readonly string CRL_DIST_POINTS = Extension.cRLDistributionPoints.getId();
		private static readonly string AUTH_INFO_ACCESS = Extension.authorityInfoAccess.getId();

		private const string RESOURCE_NAME = "org.bouncycastle.x509.CertPathReviewerMessages";

		// input parameters

		protected internal CertPath certPath;

		protected internal PKIXParameters pkixParams;

		protected internal DateTime validDate;

		// state variables

		protected internal List certs;

		protected internal int n;

		// output variables

		protected internal List[] notifications;
		protected internal List[] errors;
		protected internal TrustAnchor trustAnchor;
		protected internal PublicKey subjectPublicKey;
		protected internal PolicyNode policyTree;

		private bool initialized;

		/// <summary>
		/// Initializes the PKIXCertPathReviewer with the given <seealso cref="CertPath"/> and <seealso cref="PKIXParameters"/> params </summary>
		/// <param name="certPath"> the <seealso cref="CertPath"/> to validate </param>
		/// <param name="params"> the <seealso cref="PKIXParameters"/> to use </param>
		/// <exception cref="CertPathReviewerException"> if the certPath is empty </exception>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> is already initialized </exception>
		public virtual void init(CertPath certPath, PKIXParameters @params)
		{
			if (initialized)
			{
				throw new IllegalStateException("object is already initialized!");
			}
			initialized = true;

			// check input parameters
			if (certPath == null)
			{
				throw new NullPointerException("certPath was null");
			}
			this.certPath = certPath;

			certs = certPath.getCertificates();
			n = certs.size();
			if (certs.isEmpty())
			{
				throw new CertPathReviewerException(new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.emptyCertPath"));
			}

			pkixParams = (PKIXParameters) @params.clone();

			// 6.1.1 - Inputs

			// a) done

			// b)

			validDate = getValidDate(pkixParams);

			// c) part of pkixParams

			// d) done at the beginning of checkSignatures

			// e) f) g) part of pkixParams

			// initialize output parameters

			notifications = null;
			errors = null;
			trustAnchor = null;
			subjectPublicKey = null;
			policyTree = null;
		}

		/// <summary>
		/// Creates a PKIXCertPathReviewer and initializes it with the given <seealso cref="CertPath"/> and <seealso cref="PKIXParameters"/> params </summary>
		/// <param name="certPath"> the <seealso cref="CertPath"/> to validate </param>
		/// <param name="params"> the <seealso cref="PKIXParameters"/> to use </param>
		/// <exception cref="CertPathReviewerException"> if the certPath is empty </exception>
		public PKIXCertPathReviewer(CertPath certPath, PKIXParameters @params)
		{
			init(certPath, @params);
		}

		/// <summary>
		/// Creates an empty PKIXCertPathReviewer. Don't forget to call init() to initialize the object.
		/// </summary>
		public PKIXCertPathReviewer()
		{
			// do nothing
		}

		/// 
		/// <returns> the CertPath that was validated </returns>
		public virtual CertPath getCertPath()
		{
			return certPath;
		}

		/// 
		/// <returns> the size of the CertPath </returns>
		public virtual int getCertPathSize()
		{
			return n;
		}

		/// <summary>
		/// Returns an Array of Lists which contains a List of global error messages 
		/// and a List of error messages for each certificate in the path.
		/// The global error List is at index 0. The error lists for each certificate at index 1 to n. 
		/// The error messages are of type. </summary>
		/// <returns> the Array of Lists which contain the error messages </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual List[] getErrors()
		{
			doChecks();
			return errors;
		}

		/// <summary>
		/// Returns an List of error messages for the certificate at the given index in the CertPath.
		/// If index == -1 then the list of global errors is returned with errors not specific to a certificate. </summary>
		/// <param name="index"> the index of the certificate in the CertPath </param>
		/// <returns> List of error messages for the certificate </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual List getErrors(int index)
		{
			doChecks();
			return errors[index + 1];
		}

		/// <summary>
		/// Returns an Array of Lists which contains a List of global notification messages 
		/// and a List of botification messages for each certificate in the path.
		/// The global notificatio List is at index 0. The notification lists for each certificate at index 1 to n. 
		/// The error messages are of type. </summary>
		/// <returns> the Array of Lists which contain the notification messages </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual List[] getNotifications()
		{
			doChecks();
			return notifications;
		}

		/// <summary>
		/// Returns an List of notification messages for the certificate at the given index in the CertPath.
		/// If index == -1 then the list of global notifications is returned with notifications not specific to a certificate. </summary>
		/// <param name="index"> the index of the certificate in the CertPath </param>
		/// <returns> List of notification messages for the certificate </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual List getNotifications(int index)
		{
			doChecks();
			return notifications[index + 1];
		}

		/// 
		/// <returns> the valid policy tree, <b>null</b> if no valid policy exists. </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual PolicyNode getPolicyTree()
		{
			doChecks();
			return policyTree;
		}

		/// 
		/// <returns> the PublicKey if the last certificate in the CertPath </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual PublicKey getSubjectPublicKey()
		{
			doChecks();
			return subjectPublicKey;
		}

		/// 
		/// <returns> the TrustAnchor for the CertPath, <b>null</b> if no valid TrustAnchor was found. </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual TrustAnchor getTrustAnchor()
		{
			doChecks();
			return trustAnchor;
		}

		/// 
		/// <returns> if the CertPath is valid </returns>
		/// <exception cref="IllegalStateException"> if the <seealso cref="PKIXCertPathReviewer"/> was not initialized </exception>
		public virtual bool isValidCertPath()
		{
			doChecks();
			bool valid = true;
			for (int i = 0; i < errors.Length; i++)
			{
				if (!errors[i].isEmpty())
				{
					valid = false;
					break;
				}
			}
			return valid;
		}

		public virtual void addNotification(ErrorBundle msg)
		{
			notifications[0].add(msg);
		}

		public virtual void addNotification(ErrorBundle msg, int index)
		{
			if (index < -1 || index >= n)
			{
				throw new IndexOutOfBoundsException();
			}
			notifications[index + 1].add(msg);
		}

		public virtual void addError(ErrorBundle msg)
		{
			errors[0].add(msg);
		}

		public virtual void addError(ErrorBundle msg, int index)
		{
			if (index < -1 || index >= n)
			{
				throw new IndexOutOfBoundsException();
			}
			errors[index + 1].add(msg);
		}

		public virtual void doChecks()
		{
			if (!initialized)
			{
				throw new IllegalStateException("Object not initialized. Call init() first.");
			}
			if (notifications == null)
			{
				// initialize lists
				notifications = new List[n + 1];
				errors = new List[n + 1];

				for (int i = 0; i < notifications.Length; i++)
				{
					notifications[i] = new ArrayList();
					errors[i] = new ArrayList();
				}

				// check Signatures
				checkSignatures();

				// check Name Constraints
				checkNameConstraints();

				// check Path Length
				checkPathLength();

				// check Policy
				checkPolicy();

				// check other critical extensions
				checkCriticalExtensions();

			}
		}

		private void checkNameConstraints()
		{
			X509Certificate cert = null;

			//
			// Setup
			//

			// (b)  and (c)
			PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();

			//
			// process each certificate except the last in the path
			//
			int index;
			int i;

			try
			{
				for (index = certs.size() - 1; index > 0; index--)
				{
					i = n - index;

					//
					// certificate processing
					//    

					cert = (X509Certificate) certs.get(index);

					// b),c)

					if (!isSelfIssued(cert))
					{
						X500Principal principal = getSubjectPrincipal(cert);
						ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(principal.getEncoded()));
						ASN1Sequence dns;

						try
						{
							dns = (ASN1Sequence)aIn.readObject();
						}
						catch (IOException e)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.ncSubjectNameError", new object[] {new UntrustedInput(principal)});
							throw new CertPathReviewerException(msg,e,certPath,index);
						}

						try
						{
							nameConstraintValidator.checkPermittedDN(dns);
						}
						catch (PKIXNameConstraintValidatorException cpve)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notPermittedDN", new object[] {new UntrustedInput(principal.getName())});
							throw new CertPathReviewerException(msg,cpve,certPath,index);
						}

						try
						{
							nameConstraintValidator.checkExcludedDN(dns);
						}
						catch (PKIXNameConstraintValidatorException cpve)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.excludedDN", new object[] {new UntrustedInput(principal.getName())});
							throw new CertPathReviewerException(msg,cpve,certPath,index);
						}

						ASN1Sequence altName;
						try
						{
							altName = (ASN1Sequence)getExtensionValue(cert, SUBJECT_ALTERNATIVE_NAME);
						}
						catch (AnnotatedException ae)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.subjAltNameExtError");
							throw new CertPathReviewerException(msg,ae,certPath,index);
						}

						if (altName != null)
						{
							for (int j = 0; j < altName.size(); j++)
							{
								GeneralName name = GeneralName.getInstance(altName.getObjectAt(j));

								try
								{
									nameConstraintValidator.checkPermitted(name);
									nameConstraintValidator.checkExcluded(name);
								}
								catch (PKIXNameConstraintValidatorException cpve)
								{
									ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notPermittedEmail", new object[] {new UntrustedInput(name)});
									throw new CertPathReviewerException(msg,cpve,certPath,index);
								}
	//                            switch(o.getTagNo())            TODO - move resources to PKIXNameConstraints
	//                            {
	//                            case 1:
	//                                String email = DERIA5String.getInstance(o, true).getString();
	//
	//                                try
	//                                {
	//                                    checkPermittedEmail(permittedSubtreesEmail, email);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notPermittedEmail",
	//                                            new Object[] {new UntrustedInput(email)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//
	//                                try
	//                                {
	//                                    checkExcludedEmail(excludedSubtreesEmail, email);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.excludedEmail",
	//                                            new Object[] {new UntrustedInput(email)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//
	//                                break;
	//                            case 4:
	//                                ASN1Sequence altDN = ASN1Sequence.getInstance(o, true);
	//
	//                                try
	//                                {
	//                                    checkPermittedDN(permittedSubtreesDN, altDN);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    X509Name altDNName = new X509Name(altDN);
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notPermittedDN",
	//                                            new Object[] {new UntrustedInput(altDNName)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//
	//                                try
	//                                {
	//                                    checkExcludedDN(excludedSubtreesDN, altDN);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    X509Name altDNName = new X509Name(altDN);
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.excludedDN",
	//                                            new Object[] {new UntrustedInput(altDNName)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//
	//                                break;
	//                            case 7:
	//                                byte[] ip = ASN1OctetString.getInstance(o, true).getOctets();
	//
	//                                try
	//                                {
	//                                    checkPermittedIP(permittedSubtreesIP, ip);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notPermittedIP",
	//                                            new Object[] {IPtoString(ip)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//
	//                                try
	//                                {
	//                                    checkExcludedIP(excludedSubtreesIP, ip);
	//                                }
	//                                catch (CertPathValidatorException cpve)
	//                                {
	//                                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.excludedIP",
	//                                            new Object[] {IPtoString(ip)});
	//                                    throw new CertPathReviewerException(msg,cpve,certPath,index);
	//                                }
	//                            }
							}
						}
					}

					//
					// prepare for next certificate
					//

					//
					// (g) handle the name constraints extension
					//
					ASN1Sequence ncSeq;
					try
					{
						ncSeq = (ASN1Sequence)getExtensionValue(cert, NAME_CONSTRAINTS);
					}
					catch (AnnotatedException ae)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.ncExtError");
						throw new CertPathReviewerException(msg,ae,certPath,index);
					}

					if (ncSeq != null)
					{
						NameConstraints nc = NameConstraints.getInstance(ncSeq);

						//
						// (g) (1) permitted subtrees
						//
						GeneralSubtree[] permitted = nc.getPermittedSubtrees();
						if (permitted != null)
						{
							nameConstraintValidator.intersectPermittedSubtree(permitted);
						}

						//
						// (g) (2) excluded subtrees
						//
						GeneralSubtree[] excluded = nc.getExcludedSubtrees();
						if (excluded != null)
						{
							for (int c = 0; c != excluded.Length; c++)
							{
								 nameConstraintValidator.addExcludedSubtree(excluded[c]);
							}
						}
					}

				} // for
			}
			catch (CertPathReviewerException cpre)
			{
				addError(cpre.getErrorMessage(),cpre.getIndex());
			}

		}

		/*
		 * checks: - path length constraints and reports - total path length
		 */
		private void checkPathLength()
		{
			// init
			int maxPathLength = n;
			int totalPathLength = 0;

			X509Certificate cert = null;

			int i;
			for (int index = certs.size() - 1; index > 0; index--)
			{
				i = n - index;

				cert = (X509Certificate) certs.get(index);

				// l)

				if (!isSelfIssued(cert))
				{
					if (maxPathLength <= 0)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.pathLengthExtended");
						addError(msg);
					}
					maxPathLength--;
					totalPathLength++;
				}

				// m)

				BasicConstraints bc;
				try
				{
					bc = BasicConstraints.getInstance(getExtensionValue(cert, BASIC_CONSTRAINTS));
				}
				catch (AnnotatedException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.processLengthConstError");
					addError(msg,index);
					bc = null;
				}

				if (bc != null)
				{
					BigInteger _pathLengthConstraint = bc.getPathLenConstraint();

					if (_pathLengthConstraint != null)
					{
						int _plc = _pathLengthConstraint.intValue();

						if (_plc < maxPathLength)
						{
							maxPathLength = _plc;
						}
					}
				}

			}

			ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.totalPathLength", new object[]{Integers.valueOf(totalPathLength)});

			addNotification(msg);
		}

		/*
		 * checks: - signatures - name chaining - validity of certificates - todo:
		 * if certificate revoked (if specified in the parameters)
		 */
		private void checkSignatures()
		{
			// 1.6.1 - Inputs

			// d)

			TrustAnchor trust = null;
			X500Principal trustPrincipal = null;

			{
			// validation date
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certPathValidDate", new object[]
				{
					new TrustedInput(validDate),
					new TrustedInput(DateTime.Now)
				});
				addNotification(msg);
			}

			// find trust anchors
			try
			{
				X509Certificate cert = (X509Certificate) certs.get(certs.size() - 1);
				Collection trustColl = getTrustAnchors(cert,pkixParams.getTrustAnchors());
				if (trustColl.size() > 1)
				{
					// conflicting trust anchors                
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.conflictingTrustAnchors", new object[]{Integers.valueOf(trustColl.size()), new UntrustedInput(cert.getIssuerX500Principal())});
					addError(msg);
				}
				else if (trustColl.isEmpty())
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.noTrustAnchorFound", new object[]
					{
						new UntrustedInput(cert.getIssuerX500Principal()),
						Integers.valueOf(pkixParams.getTrustAnchors().size())
					});
					addError(msg);
				}
				else
				{
					PublicKey trustPublicKey;
					trust = (TrustAnchor) trustColl.iterator().next();
					if (trust.getTrustedCert() != null)
					{
						trustPublicKey = trust.getTrustedCert().getPublicKey();
					}
					else
					{
						trustPublicKey = trust.getCAPublicKey();
					}
					try
					{
						CertPathValidatorUtilities.verifyX509Certificate(cert, trustPublicKey, pkixParams.getSigProvider());
					}
					catch (SignatureException)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.trustButInvalidCert");
						addError(msg);
					}
					catch (Exception)
					{
						// do nothing, error occurs again later
					}
				}
			}
			catch (CertPathReviewerException cpre)
			{
				addError(cpre.getErrorMessage());
			}
			catch (Exception t)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.unknown", new object[]
				{
					new UntrustedInput(t.Message),
					new UntrustedInput(t)
				});
				addError(msg);
			}

			if (trust != null)
			{
				// get the name of the trustAnchor
				X509Certificate sign = trust.getTrustedCert();
				try
				{
					if (sign != null)
					{
						trustPrincipal = getSubjectPrincipal(sign);
					}
					else
					{
						trustPrincipal = new X500Principal(trust.getCAName());
					}
				}
				catch (IllegalArgumentException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.trustDNInvalid", new object[] {new UntrustedInput(trust.getCAName())});
					addError(msg);
				}

				// test key usages of the trust anchor
				if (sign != null)
				{
					bool[] ku = sign.getKeyUsage();
					if (ku != null && !ku[5])
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.trustKeyUsage");
						addNotification(msg);
					}
				}
			}

			// 1.6.2 - Initialization

			PublicKey workingPublicKey = null;
			X500Principal workingIssuerName = trustPrincipal;

			X509Certificate sign = null;

			AlgorithmIdentifier workingAlgId = null;
			ASN1ObjectIdentifier workingPublicKeyAlgorithm = null;
			ASN1Encodable workingPublicKeyParameters = null;

			if (trust != null)
			{
				sign = trust.getTrustedCert();

				if (sign != null)
				{
					workingPublicKey = sign.getPublicKey();
				}
				else
				{
					workingPublicKey = trust.getCAPublicKey();
				}

				try
				{
					workingAlgId = getAlgorithmIdentifier(workingPublicKey);
					workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
					workingPublicKeyParameters = workingAlgId.getParameters();
				}
				catch (CertPathValidatorException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.trustPubKeyError");
					addError(msg);
					workingAlgId = null;
				}

			}

			// Basic cert checks

			X509Certificate cert = null;
			int i;

			for (int index = certs.size() - 1; index >= 0; index--)
			{
				//
				// i as defined in the algorithm description
				//
				i = n - index;

				//
				// set certificate to be checked in this round
				// sign and workingPublicKey and workingIssuerName are set
				// at the end of the for loop and initialied the
				// first time from the TrustAnchor
				//
				cert = (X509Certificate) certs.get(index);

				// verify signature
				if (workingPublicKey != null)
				{
					try
					{
						CertPathValidatorUtilities.verifyX509Certificate(cert, workingPublicKey, pkixParams.getSigProvider());
					}
					catch (GeneralSecurityException ex)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.signatureNotVerified", new object[] {ex.Message, ex, ex.GetType().getName()});
						addError(msg,index);
					}
				}
				else if (isSelfIssued(cert))
				{
					try
					{
						CertPathValidatorUtilities.verifyX509Certificate(cert, cert.getPublicKey(), pkixParams.getSigProvider());
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.rootKeyIsValidButNotATrustAnchor");
						addError(msg, index);
					}
					catch (GeneralSecurityException ex)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.signatureNotVerified", new object[] {ex.Message, ex, ex.GetType().getName()});
						addError(msg,index);
					}
				}
				else
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.NoIssuerPublicKey");
					// if there is an authority key extension add the serial and issuer of the missing certificate
					byte[] akiBytes = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
					if (akiBytes != null)
					{
						AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(DEROctetString.getInstance(akiBytes).getOctets());
						GeneralNames issuerNames = aki.getAuthorityCertIssuer();
						if (issuerNames != null)
						{
							GeneralName name = issuerNames.getNames()[0];
							BigInteger serial = aki.getAuthorityCertSerialNumber();
							if (serial != null)
							{
								object[] extraArgs = new object[]
								{
									new LocaleString(RESOURCE_NAME, "missingIssuer"),
									@" """,
									name,
									@""" ",
									new LocaleString(RESOURCE_NAME, "missingSerial"),
									" ",
									serial
								};
								msg.setExtraArguments(extraArgs);
							}
						}
					}
					addError(msg,index);
				}

				// certificate valid?
				try
				{
					cert.checkValidity(validDate);
				}
				catch (CertificateNotYetValidException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certificateNotYetValid", new object[] {new TrustedInput(cert.getNotBefore())});
					addError(msg,index);
				}
				catch (CertificateExpiredException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certificateExpired", new object[] {new TrustedInput(cert.getNotAfter())});
					addError(msg,index);
				}

				// certificate revoked?
				if (pkixParams.isRevocationEnabled())
				{
					// read crl distribution points extension
					CRLDistPoint crlDistPoints = null;
					try
					{
						ASN1Primitive crl_dp = getExtensionValue(cert,CRL_DIST_POINTS);
						if (crl_dp != null)
						{
							crlDistPoints = CRLDistPoint.getInstance(crl_dp);
						}
					}
					catch (AnnotatedException)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlDistPtExtError");
						addError(msg,index);
					}

					// read authority information access extension
					AuthorityInformationAccess authInfoAcc = null;
					try
					{
						ASN1Primitive auth_info_acc = getExtensionValue(cert,AUTH_INFO_ACCESS);
						if (auth_info_acc != null)
						{
							authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
						}
					}
					catch (AnnotatedException)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlAuthInfoAccError");
						addError(msg,index);
					}

					Vector crlDistPointUrls = getCRLDistUrls(crlDistPoints);
					Vector ocspUrls = getOCSPUrls(authInfoAcc);

					// add notifications with the crl distribution points

					// output crl distribution points
					Iterator urlIt = crlDistPointUrls.iterator();
					while (urlIt.hasNext())
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlDistPoint", new object[] {new UntrustedUrlInput(urlIt.next())});
						addNotification(msg,index);
					}

					// output ocsp urls
					urlIt = ocspUrls.iterator();
					while (urlIt.hasNext())
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.ocspLocation", new object[] {new UntrustedUrlInput(urlIt.next())});
						addNotification(msg,index);
					}

					// TODO also support Netscapes revocation-url and/or OCSP instead of CRLs for revocation checking
					// check CRLs
					try
					{
						checkRevocation(pkixParams, cert, validDate, sign, workingPublicKey, crlDistPointUrls, ocspUrls, index);
					}
					catch (CertPathReviewerException cpre)
					{
						addError(cpre.getErrorMessage(),index);
					}
				}

				// certificate issuer correct
				if (workingIssuerName != null && !cert.getIssuerX500Principal().Equals(workingIssuerName))
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certWrongIssuer", new object[] {workingIssuerName.getName(), cert.getIssuerX500Principal().getName()});
					addError(msg,index);
				}

				//
				// prepare for next certificate
				//
				if (i != n)
				{

					if (cert != null && cert.getVersion() == 1)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noCACert");
						addError(msg,index);
					}

					// k)

					BasicConstraints bc;
					try
					{
						bc = BasicConstraints.getInstance(getExtensionValue(cert, BASIC_CONSTRAINTS));
						if (bc != null)
						{
							if (!bc.isCA())
							{
								ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noCACert");
								addError(msg,index);
							}
						}
						else
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noBasicConstraints");
							addError(msg,index);
						}
					}
					catch (AnnotatedException)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.errorProcesingBC");
						addError(msg,index);
					}

					// n)

					bool[] _usage = cert.getKeyUsage();

					if ((_usage != null) && !_usage[KEY_CERT_SIGN])
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noCertSign");
						addError(msg,index);
					}

				} // if

				// set signing certificate for next round
				sign = cert;

				// c)

				workingIssuerName = cert.getSubjectX500Principal();

				// d) e) f)

				try
				{
					workingPublicKey = getNextWorkingKey(certs, index);
					workingAlgId = getAlgorithmIdentifier(workingPublicKey);
					workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
					workingPublicKeyParameters = workingAlgId.getParameters();
				}
				catch (CertPathValidatorException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.pubKeyError");
					addError(msg,index);
					workingAlgId = null;
					workingPublicKeyAlgorithm = null;
					workingPublicKeyParameters = null;
				}

			} // for

			trustAnchor = trust;
			subjectPublicKey = workingPublicKey;
		}

		private void checkPolicy()
		{
			//
			// 6.1.1 Inputs
			//

			// c) Initial Policy Set

			Set userInitialPolicySet = pkixParams.getInitialPolicies();

			// e) f) g) are part of pkixParams

			//
			// 6.1.2 Initialization
			//

			// a) valid policy tree

			List[] policyNodes = new ArrayList[n + 1];
			for (int j = 0; j < policyNodes.Length; j++)
			{
				policyNodes[j] = new ArrayList();
			}

			Set policySet = new HashSet();

			policySet.add(ANY_POLICY);

			PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, null, new HashSet(), ANY_POLICY, false);

			policyNodes[0].add(validPolicyTree);

			// d) explicit policy

			int explicitPolicy;
			if (pkixParams.isExplicitPolicyRequired())
			{
				explicitPolicy = 0;
			}
			else
			{
				explicitPolicy = n + 1;
			}

			// e) inhibit any policy

			int inhibitAnyPolicy;
			if (pkixParams.isAnyPolicyInhibited())
			{
				inhibitAnyPolicy = 0;
			}
			else
			{
				inhibitAnyPolicy = n + 1;
			}

			// f) policy mapping

			int policyMapping;
			if (pkixParams.isPolicyMappingInhibited())
			{
				policyMapping = 0;
			}
			else
			{
				policyMapping = n + 1;
			}

			Set acceptablePolicies = null;

			//
			// 6.1.3 Basic Certificate processing
			//

			X509Certificate cert = null;
			int index;
			int i;

			try
			{
				for (index = certs.size() - 1; index >= 0; index--)
				{
					// i as defined in the algorithm description
					i = n - index;

					// set certificate to be checked in this round
					cert = (X509Certificate) certs.get(index);

					// d) process policy information

					ASN1Sequence certPolicies;
					try
					{
						certPolicies = (ASN1Sequence) getExtensionValue(cert, CERTIFICATE_POLICIES);
					}
					catch (AnnotatedException ae)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyExtError");
						throw new CertPathReviewerException(msg,ae,certPath,index);
					}
					if (certPolicies != null && validPolicyTree != null)
					{

						// d) 1)

						Enumeration e = certPolicies.getObjects();
						Set pols = new HashSet();

						while (e.hasMoreElements())
						{
							PolicyInformation pInfo = PolicyInformation.getInstance(e.nextElement());
							ASN1ObjectIdentifier pOid = pInfo.getPolicyIdentifier();

							pols.add(pOid.getId());

							if (!ANY_POLICY.Equals(pOid.getId()))
							{
								Set pq;
								try
								{
									pq = getQualifierSet(pInfo.getPolicyQualifiers());
								}
								catch (CertPathValidatorException cpve)
								{
									ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyQualifierError");
									throw new CertPathReviewerException(msg,cpve,certPath,index);
								}

								bool match = processCertD1i(i, policyNodes, pOid, pq);

								if (!match)
								{
									processCertD1ii(i, policyNodes, pOid, pq);
								}
							}
						}

						if (acceptablePolicies == null || acceptablePolicies.contains(ANY_POLICY))
						{
							acceptablePolicies = pols;
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

							acceptablePolicies = t1;
						}

						// d) 2)

						if ((inhibitAnyPolicy > 0) || ((i < n) && isSelfIssued(cert)))
						{
							e = certPolicies.getObjects();

							while (e.hasMoreElements())
							{
								PolicyInformation pInfo = PolicyInformation.getInstance(e.nextElement());

								if (ANY_POLICY.Equals(pInfo.getPolicyIdentifier().getId()))
								{
									Set _apq;
									try
									{
										_apq = getQualifierSet(pInfo.getPolicyQualifiers());
									}
									catch (CertPathValidatorException cpve)
									{
										ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyQualifierError");
										throw new CertPathReviewerException(msg,cpve,certPath,index);
									}
									List _nodes = policyNodes[i - 1];

									for (int k = 0; k < _nodes.size(); k++)
									{
										PKIXPolicyNode _node = (PKIXPolicyNode) _nodes.get(k);

										Iterator _policySetIter = _node.getExpectedPolicies().iterator();
										while (_policySetIter.hasNext())
										{
											object _tmp = _policySetIter.next();

											string _policy;
											if (_tmp is string)
											{
												_policy = (string) _tmp;
											}
											else if (_tmp is ASN1ObjectIdentifier)
											{
												_policy = ((ASN1ObjectIdentifier) _tmp).getId();
											}
											else
											{
												continue;
											}

											bool _found = false;
											Iterator _childrenIter = _node.getChildren();

											while (_childrenIter.hasNext())
											{
												PKIXPolicyNode _child = (PKIXPolicyNode) _childrenIter.next();

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

						//
						// (d) (3)
						//
						for (int j = (i - 1); j >= 0; j--)
						{
							List nodes = policyNodes[j];

							for (int k = 0; k < nodes.size(); k++)
							{
								PKIXPolicyNode node = (PKIXPolicyNode) nodes.get(k);
								if (!node.hasChildren())
								{
									validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node);
									if (validPolicyTree == null)
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
							bool critical = criticalExtensionOids.contains(CERTIFICATE_POLICIES);

							List nodes = policyNodes[i];
							for (int j = 0; j < nodes.size(); j++)
							{
								PKIXPolicyNode node = (PKIXPolicyNode) nodes.get(j);
								node.setCritical(critical);
							}
						}

					}

					// e)

					if (certPolicies == null)
					{
						validPolicyTree = null;
					}

					// f)

					if (explicitPolicy <= 0 && validPolicyTree == null)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noValidPolicyTree");
						throw new CertPathReviewerException(msg);
					}

					//
					// 6.1.4 preparation for next Certificate
					//

					if (i != n)
					{

						// a)

						ASN1Primitive pm;
						try
						{
							pm = getExtensionValue(cert, POLICY_MAPPINGS);
						}
						catch (AnnotatedException ae)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyMapExtError");
							throw new CertPathReviewerException(msg,ae,certPath,index);
						}

						if (pm != null)
						{
							ASN1Sequence mappings = (ASN1Sequence) pm;
							for (int j = 0; j < mappings.size(); j++)
							{
								ASN1Sequence mapping = (ASN1Sequence) mappings.getObjectAt(j);
								ASN1ObjectIdentifier ip_id = (ASN1ObjectIdentifier) mapping.getObjectAt(0);
								ASN1ObjectIdentifier sp_id = (ASN1ObjectIdentifier) mapping.getObjectAt(1);
								if (ANY_POLICY.Equals(ip_id.getId()))
								{
									ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.invalidPolicyMapping");
									throw new CertPathReviewerException(msg,certPath,index);
								}
								if (ANY_POLICY.Equals(sp_id.getId()))
								{
									ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.invalidPolicyMapping");
									throw new CertPathReviewerException(msg,certPath,index);
								}
							}
						}

						// b)

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
									try
									{
										prepareNextCertB1(i,policyNodes,id_p,m_idp,cert);
									}
									catch (AnnotatedException ae)
									{
										// error processing certificate policies extension
										ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyExtError");
										throw new CertPathReviewerException(msg,ae,certPath,index);
									}
									catch (CertPathValidatorException cpve)
									{
										// error building qualifier set
										ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyQualifierError");
										throw new CertPathReviewerException(msg,cpve,certPath,index);
									}

									//
									// (2)
									// 
								}
								else if (policyMapping <= 0)
								{
									validPolicyTree = prepareNextCertB2(i,policyNodes,id_p,validPolicyTree);
								}

							}
						}

						//
						// h)
						//

						if (!isSelfIssued(cert))
						{

							// (1)
							if (explicitPolicy != 0)
							{
								explicitPolicy--;
							}

							// (2)
							if (policyMapping != 0)
							{
								policyMapping--;
							}

							// (3)
							if (inhibitAnyPolicy != 0)
							{
								inhibitAnyPolicy--;
							}

						}

						//
						// i)
						//

						try
						{
							ASN1Sequence pc = (ASN1Sequence) getExtensionValue(cert,POLICY_CONSTRAINTS);
							if (pc != null)
							{
								Enumeration policyConstraints = pc.getObjects();

								while (policyConstraints.hasMoreElements())
								{
									ASN1TaggedObject constraint = (ASN1TaggedObject) policyConstraints.nextElement();
									int tmpInt;

									switch (constraint.getTagNo())
									{
									case 0:
										tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
										if (tmpInt < explicitPolicy)
										{
											explicitPolicy = tmpInt;
										}
										break;
									case 1:
										tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
										if (tmpInt < policyMapping)
										{
											policyMapping = tmpInt;
										}
									break;
									}
								}
							}
						}
						catch (AnnotatedException)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyConstExtError");
							throw new CertPathReviewerException(msg,certPath,index);
						}

						//
						// j)
						//

						try
						{
							ASN1Integer iap = (ASN1Integer)getExtensionValue(cert, INHIBIT_ANY_POLICY);

							if (iap != null)
							{
								int _inhibitAnyPolicy = iap.getValue().intValue();

								if (_inhibitAnyPolicy < inhibitAnyPolicy)
								{
									inhibitAnyPolicy = _inhibitAnyPolicy;
								}
							}
						}
						catch (AnnotatedException)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyInhibitExtError");
							throw new CertPathReviewerException(msg,certPath,index);
						}
					}

				}

				//
				// 6.1.5 Wrap up
				//

				//
				// a)
				//

				if (!isSelfIssued(cert) && explicitPolicy > 0)
				{
					explicitPolicy--;
				}

				//
				// b)
				//

				try
				{
					ASN1Sequence pc = (ASN1Sequence) getExtensionValue(cert, POLICY_CONSTRAINTS);
					if (pc != null)
					{
						Enumeration policyConstraints = pc.getObjects();

						while (policyConstraints.hasMoreElements())
						{
							ASN1TaggedObject constraint = (ASN1TaggedObject)policyConstraints.nextElement();
							switch (constraint.getTagNo())
							{
							case 0:
								int tmpInt = ASN1Integer.getInstance(constraint, false).getValue().intValue();
								if (tmpInt == 0)
								{
									explicitPolicy = 0;
								}
								break;
							}
						}
					}
				}
				catch (AnnotatedException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.policyConstExtError");
					throw new CertPathReviewerException(msg,certPath,index);
				}


				//
				// (g)
				//
				PKIXPolicyNode intersection;


				//
				// (g) (i)
				//
				if (validPolicyTree == null)
				{
					if (pkixParams.isExplicitPolicyRequired())
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.explicitPolicy");
						throw new CertPathReviewerException(msg,certPath,index);
					}
					intersection = null;
				}
				else if (isAnyPolicy(userInitialPolicySet)) // (g) (ii)
				{
					if (pkixParams.isExplicitPolicyRequired())
					{
						if (acceptablePolicies.isEmpty())
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.explicitPolicy");
							throw new CertPathReviewerException(msg,certPath,index);
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

									if (ANY_POLICY.Equals(_node.getValidPolicy()))
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
									//validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, _node);
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
											validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node);
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
					// This implementation is not exactly same as the one described in RFC3280.
					// However, as far as the validation result is concerned, both produce 
					// adequate result. The only difference is whether AnyPolicy is remain 
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

							if (ANY_POLICY.Equals(_node.getValidPolicy()))
							{
								Iterator _iter = _node.getChildren();
								while (_iter.hasNext())
								{
									PKIXPolicyNode _c_node = (PKIXPolicyNode)_iter.next();
									if (!ANY_POLICY.Equals(_c_node.getValidPolicy()))
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
							validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, _node);
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
									validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node);
								}
							}
						}
					}

					intersection = validPolicyTree;
				}

				if ((explicitPolicy <= 0) && (intersection == null))
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.invalidPolicy");
					throw new CertPathReviewerException(msg);
				}

				validPolicyTree = intersection;
			}
			catch (CertPathReviewerException cpre)
			{
				addError(cpre.getErrorMessage(),cpre.getIndex());
				validPolicyTree = null;
			}
		}

		private void checkCriticalExtensions()
		{
			//      
			// initialise CertPathChecker's
			//
			List pathCheckers = pkixParams.getCertPathCheckers();
			Iterator certIter = pathCheckers.iterator();

			try
			{
				try
				{
					while (certIter.hasNext())
					{
						((PKIXCertPathChecker)certIter.next()).init(false);
					}
				}
				catch (CertPathValidatorException cpve)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certPathCheckerError", new object[] {cpve.Message, cpve, cpve.GetType().getName()});
					throw new CertPathReviewerException(msg,cpve);
				}

				//
				// process critical extesions for each certificate
				//

				X509Certificate cert = null;

				int index;

				for (index = certs.size() - 1; index >= 0; index--)
				{
					cert = (X509Certificate) certs.get(index);

					Set criticalExtensions = cert.getCriticalExtensionOIDs();
					if (criticalExtensions == null || criticalExtensions.isEmpty())
					{
						continue;
					}
					// remove already processed extensions
					criticalExtensions.remove(KEY_USAGE);
					criticalExtensions.remove(CERTIFICATE_POLICIES);
					criticalExtensions.remove(POLICY_MAPPINGS);
					criticalExtensions.remove(INHIBIT_ANY_POLICY);
					criticalExtensions.remove(ISSUING_DISTRIBUTION_POINT);
					criticalExtensions.remove(DELTA_CRL_INDICATOR);
					criticalExtensions.remove(POLICY_CONSTRAINTS);
					criticalExtensions.remove(BASIC_CONSTRAINTS);
					criticalExtensions.remove(SUBJECT_ALTERNATIVE_NAME);
					criticalExtensions.remove(NAME_CONSTRAINTS);

					// process qcStatements extension
					if (criticalExtensions.contains(QC_STATEMENT))
					{
						if (processQcStatements(cert,index))
						{
							criticalExtensions.remove(QC_STATEMENT);
						}
					}

					Iterator tmpIter = pathCheckers.iterator();
					while (tmpIter.hasNext())
					{
						try
						{
							((PKIXCertPathChecker)tmpIter.next()).check(cert, criticalExtensions);
						}
						catch (CertPathValidatorException e)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.criticalExtensionError", new object[] {e.Message, e, e.GetType().getName()});
							throw new CertPathReviewerException(msg,e.InnerException,certPath,index);
						}
					}
					if (!criticalExtensions.isEmpty())
					{
						ErrorBundle msg;
						Iterator it = criticalExtensions.iterator();
						while (it.hasNext())
						{
							msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.unknownCriticalExt", new object[] {new ASN1ObjectIdentifier((string) it.next())});
							addError(msg, index);
						}
					}
				}
			}
			catch (CertPathReviewerException cpre)
			{
				addError(cpre.getErrorMessage(),cpre.getIndex());
			}
		}

		private bool processQcStatements(X509Certificate cert, int index)
		{
			try
			{
				bool unknownStatement = false;

				ASN1Sequence qcSt = (ASN1Sequence) getExtensionValue(cert,QC_STATEMENT);
				for (int j = 0; j < qcSt.size(); j++)
				{
					QCStatement stmt = QCStatement.getInstance(qcSt.getObjectAt(j));
					if (QCStatement.id_etsi_qcs_QcCompliance.Equals(stmt.getStatementId()))
					{
						// process statement - just write a notification that the certificate contains this statement
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcEuCompliance");
						addNotification(msg,index);
					}
					else if (QCStatement.id_qcs_pkixQCSyntax_v1.Equals(stmt.getStatementId()))
					{
						// process statement - just recognize the statement
					}
					else if (QCStatement.id_etsi_qcs_QcSSCD.Equals(stmt.getStatementId()))
					{
						// process statement - just write a notification that the certificate contains this statement
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcSSCD");
						addNotification(msg,index);
					}
					else if (QCStatement.id_etsi_qcs_LimiteValue.Equals(stmt.getStatementId()))
					{
						// process statement - write a notification containing the limit value
						MonetaryValue limit = MonetaryValue.getInstance(stmt.getStatementInfo());
						Iso4217CurrencyCode currency = limit.getCurrency();
						double value = limit.getAmount().doubleValue() * Math.pow(10,limit.getExponent().doubleValue());
						ErrorBundle msg;
						if (limit.getCurrency().isAlphabetic())
						{
							msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcLimitValueAlpha", new object[] {limit.getCurrency().getAlphabetic(), new TrustedInput(new double?(value)), limit});
						}
						else
						{
							msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcLimitValueNum", new object[]{Integers.valueOf(limit.getCurrency().getNumeric()), new TrustedInput(new double?(value)), limit});
						}
						addNotification(msg,index);
					}
					else
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcUnknownStatement", new object[] {stmt.getStatementId(), new UntrustedInput(stmt)});
						addNotification(msg,index);
						unknownStatement = true;
					}
				}

				return !unknownStatement;
			}
			catch (AnnotatedException)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.QcStatementExtError");
				addError(msg,index);
			}

			return false;
		}

		private string IPtoString(byte[] ip)
		{
			string result;
			try
			{
				result = InetAddress.getByAddress(ip).getHostAddress();
			}
			catch (Exception)
			{
				StringBuffer b = new StringBuffer();

				for (int i = 0; i != ip.Length; i++)
				{
					b.append((ip[i] & 0xff).ToString("x"));
					b.append(' ');
				}

				result = b.ToString();
			}

			return result;
		}

		public virtual void checkRevocation(PKIXParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate sign, PublicKey workingPublicKey, Vector crlDistPointUrls, Vector ocspUrls, int index)
		{
			checkCRLs(paramsPKIX, cert, validDate, sign, workingPublicKey, crlDistPointUrls, index);
		}

		public virtual void checkCRLs(PKIXParameters paramsPKIX, X509Certificate cert, DateTime validDate, X509Certificate sign, PublicKey workingPublicKey, Vector crlDistPointUrls, int index)
		{
			X509CRLStoreSelector crlselect;
			crlselect = new X509CRLStoreSelector();

			try
			{
				crlselect.addIssuerName(getEncodedIssuerPrincipal(cert).getEncoded());
			}
			catch (IOException e)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlIssuerException");
				throw new CertPathReviewerException(msg,e);
			}

			crlselect.setCertificateChecking(cert);

			Iterator crl_iter;
			try
			{
				Collection crl_coll = CRL_UTIL.findCRLs(crlselect, paramsPKIX);
				crl_iter = crl_coll.iterator();

				if (crl_coll.isEmpty())
				{
					// notifcation - no local crls found
					crl_coll = CRL_UTIL.findCRLs(new X509CRLStoreSelector(),paramsPKIX);
					Iterator it = crl_coll.iterator();
					List nonMatchingCrlNames = new ArrayList();
					while (it.hasNext())
					{
						nonMatchingCrlNames.add(((X509CRL) it.next()).getIssuerX500Principal());
					}
					int numbOfCrls = nonMatchingCrlNames.size();
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.noCrlInCertstore", new object[]
					{
						new UntrustedInput(crlselect.getIssuerNames()),
						new UntrustedInput(nonMatchingCrlNames),
						Integers.valueOf(numbOfCrls)
					});
					addNotification(msg,index);
				}

			}
			catch (AnnotatedException ae)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlExtractionError", new object[] {ae.InnerException.Message, ae.InnerException, ae.InnerException.GetType().getName()});
				addError(msg,index);
				crl_iter = (new ArrayList()).iterator();
			}
			bool validCrlFound = false;
			X509CRL crl = null;
			while (crl_iter.hasNext())
			{
				crl = (X509CRL)crl_iter.next();

				if (crl.getNextUpdate() == null || paramsPKIX.getDate().before(crl.getNextUpdate()))
				{
					validCrlFound = true;
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.localValidCRL", new object[]
					{
						new TrustedInput(crl.getThisUpdate()),
						new TrustedInput(crl.getNextUpdate())
					});
					addNotification(msg,index);
					break;
				}
				else
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.localInvalidCRL", new object[]
					{
						new TrustedInput(crl.getThisUpdate()),
						new TrustedInput(crl.getNextUpdate())
					});
					addNotification(msg,index);
				}
			}

			// if no valid crl was found in the CertStores try to get one from a
			// crl distribution point
			if (!validCrlFound)
			{
				X509CRL onlineCRL = null;
				Iterator urlIt = crlDistPointUrls.iterator();
				while (urlIt.hasNext())
				{
					try
					{
						string location = (string) urlIt.next();
						onlineCRL = getCRL(location);
						if (onlineCRL != null)
						{
							// check if crl issuer is correct
							if (!cert.getIssuerX500Principal().Equals(onlineCRL.getIssuerX500Principal()))
							{
								ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.onlineCRLWrongCA", new object[]
								{
									new UntrustedInput(onlineCRL.getIssuerX500Principal().getName()),
									new UntrustedInput(cert.getIssuerX500Principal().getName()),
									new UntrustedUrlInput(location)
								});
								addNotification(msg,index);
								continue;
							}

							if (onlineCRL.getNextUpdate() == null || pkixParams.getDate().before(onlineCRL.getNextUpdate()))
							{
								validCrlFound = true;
								ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.onlineValidCRL", new object[]
								{
									new TrustedInput(onlineCRL.getThisUpdate()),
									new TrustedInput(onlineCRL.getNextUpdate()),
									new UntrustedUrlInput(location)
								});
								addNotification(msg,index);
								crl = onlineCRL;
								break;
							}
							else
							{
								ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.onlineInvalidCRL", new object[]
								{
									new TrustedInput(onlineCRL.getThisUpdate()),
									new TrustedInput(onlineCRL.getNextUpdate()),
									new UntrustedUrlInput(location)
								});
								addNotification(msg,index);
							}
						}
					}
					catch (CertPathReviewerException cpre)
					{
						addNotification(cpre.getErrorMessage(),index);
					}
				}
			}

			// check the crl
			X509CRLEntry crl_entry;
			if (crl != null)
			{
				if (sign != null)
				{
					bool[] keyusage = sign.getKeyUsage();

					if (keyusage != null && (keyusage.Length < 7 || !keyusage[CRL_SIGN]))
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noCrlSigningPermited");
						throw new CertPathReviewerException(msg);
					}
				}

				if (workingPublicKey != null)
				{
					try
					{
						crl.verify(workingPublicKey, "BC");
					}
					catch (Exception e)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlVerifyFailed");
						throw new CertPathReviewerException(msg,e);
					}
				}
				else // issuer public key not known
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlNoIssuerPublicKey");
					throw new CertPathReviewerException(msg);
				}

				crl_entry = crl.getRevokedCertificate(cert.getSerialNumber());
				if (crl_entry != null)
				{
					string reason = null;

					if (crl_entry.hasExtensions())
					{
						ASN1Enumerated reasonCode;
						try
						{
							reasonCode = ASN1Enumerated.getInstance(getExtensionValue(crl_entry, Extension.reasonCode.getId()));
						}
						catch (AnnotatedException ae)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlReasonExtError");
							throw new CertPathReviewerException(msg,ae);
						}
						if (reasonCode != null)
						{
							reason = crlReasons[reasonCode.getValue().intValue()];
						}
					}

					if (string.ReferenceEquals(reason, null))
					{
						reason = crlReasons[7]; // unknown
					}

					// i18n reason
					LocaleString ls = new LocaleString(RESOURCE_NAME, reason);

					if (!validDate < crl_entry.getRevocationDate())
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.certRevoked", new object[]
						{
							new TrustedInput(crl_entry.getRevocationDate()),
							ls
						});
						throw new CertPathReviewerException(msg);
					}
					else // cert was revoked after validation date
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.revokedAfterValidation", new object[]
						{
							new TrustedInput(crl_entry.getRevocationDate()),
							ls
						});
						addNotification(msg,index);
					}
				}
				else // cert is not revoked
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.notRevoked");
					addNotification(msg,index);
				}

				//
				// warn if a new crl is available
				//
				if (crl.getNextUpdate() != null && crl.getNextUpdate().before(pkixParams.getDate()))
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlUpdateAvailable", new object[] {new TrustedInput(crl.getNextUpdate())});
					addNotification(msg,index);
				}

				//
				// check the DeltaCRL indicator, base point and the issuing distribution point
				//
				ASN1Primitive idp;
				try
				{
					idp = getExtensionValue(crl, ISSUING_DISTRIBUTION_POINT);
				}
				catch (AnnotatedException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.distrPtExtError");
					throw new CertPathReviewerException(msg);
				}
				ASN1Primitive dci;
				try
				{
					dci = getExtensionValue(crl, DELTA_CRL_INDICATOR);
				}
				catch (AnnotatedException)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.deltaCrlExtError");
					throw new CertPathReviewerException(msg);
				}

				if (dci != null)
				{
					X509CRLStoreSelector baseSelect = new X509CRLStoreSelector();

					try
					{
						baseSelect.addIssuerName(getIssuerPrincipal(crl).getEncoded());
					}
					catch (IOException e)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlIssuerException");
						throw new CertPathReviewerException(msg,e);
					}

					baseSelect.setMinCRLNumber(((ASN1Integer)dci).getPositiveValue());
					try
					{
						baseSelect.setMaxCRLNumber(((ASN1Integer)getExtensionValue(crl, CRL_NUMBER)).getPositiveValue().subtract(BigInteger.valueOf(1)));
					}
					catch (AnnotatedException ae)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlNbrExtError");
						throw new CertPathReviewerException(msg,ae);
					}

					bool foundBase = false;
					Iterator it;
					try
					{
						it = CRL_UTIL.findCRLs(baseSelect, paramsPKIX).iterator();
					}
					catch (AnnotatedException ae)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlExtractionError");
						throw new CertPathReviewerException(msg,ae);
					}
					while (it.hasNext())
					{
						X509CRL @base = (X509CRL)it.next();

						ASN1Primitive baseIdp;
						try
						{
							baseIdp = getExtensionValue(@base, ISSUING_DISTRIBUTION_POINT);
						}
						catch (AnnotatedException ae)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.distrPtExtError");
							throw new CertPathReviewerException(msg,ae);
						}

						if (idp == null)
						{
							if (baseIdp == null)
							{
								foundBase = true;
								break;
							}
						}
						else
						{
							if (idp.Equals(baseIdp))
							{
								foundBase = true;
								break;
							}
						}
					}

					if (!foundBase)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noBaseCRL");
						throw new CertPathReviewerException(msg);
					}
				}

				if (idp != null)
				{
					IssuingDistributionPoint p = IssuingDistributionPoint.getInstance(idp);
					BasicConstraints bc = null;
					try
					{
						bc = BasicConstraints.getInstance(getExtensionValue(cert, BASIC_CONSTRAINTS));
					}
					catch (AnnotatedException ae)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlBCExtError");
						throw new CertPathReviewerException(msg,ae);
					}

					if (p.onlyContainsUserCerts() && (bc != null && bc.isCA()))
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlOnlyUserCert");
						throw new CertPathReviewerException(msg);
					}

					if (p.onlyContainsCACerts() && (bc == null || !bc.isCA()))
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlOnlyCaCert");
						throw new CertPathReviewerException(msg);
					}

					if (p.onlyContainsAttributeCerts())
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.crlOnlyAttrCert");
						throw new CertPathReviewerException(msg);
					}
				}
			}

			if (!validCrlFound)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.noValidCrlFound");
				throw new CertPathReviewerException(msg);
			}

		}

		public virtual Vector getCRLDistUrls(CRLDistPoint crlDistPoints)
		{
			Vector urls = new Vector();

			if (crlDistPoints != null)
			{
				DistributionPoint[] distPoints = crlDistPoints.getDistributionPoints();
				for (int i = 0; i < distPoints.Length; i++)
				{
					DistributionPointName dp_name = distPoints[i].getDistributionPoint();
					if (dp_name.getType() == DistributionPointName.FULL_NAME)
					{
						GeneralName[] generalNames = GeneralNames.getInstance(dp_name.getName()).getNames();
						for (int j = 0; j < generalNames.Length; j++)
						{
							if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
							{
								string url = ((DERIA5String) generalNames[j].getName()).getString();
								urls.add(url);
							}
						}
					}
				}
			}
			return urls;
		}

		public virtual Vector getOCSPUrls(AuthorityInformationAccess authInfoAccess)
		{
			Vector urls = new Vector();

			if (authInfoAccess != null)
			{
				AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
				for (int i = 0; i < ads.Length; i++)
				{
					if (ads[i].getAccessMethod().Equals(AccessDescription.id_ad_ocsp))
					{
						GeneralName name = ads[i].getAccessLocation();
						if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
						{
							string url = ((DERIA5String) name.getName()).getString();
							urls.add(url);
						}
					}
				}
			}

			return urls;
		}

		private X509CRL getCRL(string location)
		{
			X509CRL result = null;
			try
			{
				URL url = new URL(location);

				if (url.getProtocol().Equals("http") || url.getProtocol().Equals("https"))
				{
					HttpURLConnection conn = (HttpURLConnection) url.openConnection();
					conn.setUseCaches(false);
					//conn.setConnectTimeout(2000);
					conn.setDoInput(true);
					conn.connect();
					if (conn.getResponseCode() == HttpURLConnection.HTTP_OK)
					{
						CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
						result = (X509CRL) cf.generateCRL(conn.getInputStream());
					}
					else
					{
						throw new Exception(conn.getResponseMessage());
					}
				}
			}
			catch (Exception e)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "CertPathReviewer.loadCrlDistPointError", new object[]
				{
					new UntrustedInput(location),
					e.Message,
					e,
					e.GetType().getName()
				});
				throw new CertPathReviewerException(msg);
			}
			return result;
		}

		public virtual Collection getTrustAnchors(X509Certificate cert, Set trustanchors)
		{
			Collection trustColl = new ArrayList();
			Iterator it = trustanchors.iterator();

			X509CertSelector certSelectX509 = new X509CertSelector();

			try
			{
				certSelectX509.setSubject(getEncodedIssuerPrincipal(cert).getEncoded());
				byte[] ext = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());

				if (ext != null)
				{
					ASN1OctetString oct = (ASN1OctetString)ASN1Primitive.fromByteArray(ext);
					AuthorityKeyIdentifier authID = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));

					certSelectX509.setSerialNumber(authID.getAuthorityCertSerialNumber());
					byte[] keyID = authID.getKeyIdentifier();
					if (keyID != null)
					{
						certSelectX509.setSubjectKeyIdentifier((new DEROctetString(keyID)).getEncoded());
					}
				}
			}
			catch (IOException)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"CertPathReviewer.trustAnchorIssuerError");
				throw new CertPathReviewerException(msg);
			}

			while (it.hasNext())
			{
				TrustAnchor trust = (TrustAnchor) it.next();
				if (trust.getTrustedCert() != null)
				{
					if (certSelectX509.match(trust.getTrustedCert()))
					{
						trustColl.add(trust);
					}
				}
				else if (trust.getCAName() != null && trust.getCAPublicKey() != null)
				{
					X500Principal certIssuer = getEncodedIssuerPrincipal(cert);
					X500Principal caName = new X500Principal(trust.getCAName());
					if (certIssuer.Equals(caName))
					{
						trustColl.add(trust);
					}
				}
			}
			return trustColl;
		}
	}

}