using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.mail.smime.validator
{


	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using Time = org.bouncycastle.asn1.cms.Time;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AttributeTypeAndValue = org.bouncycastle.asn1.x500.AttributeTypeAndValue;
	using RDN = org.bouncycastle.asn1.x500.RDN;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using JcaCertStoreBuilder = org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using JcaX509CertSelectorConverter = org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using TrustedInput = org.bouncycastle.i18n.filter.TrustedInput;
	using UntrustedInput = org.bouncycastle.i18n.filter.UntrustedInput;
	using Integers = org.bouncycastle.util.Integers;
	using CertPathReviewerException = org.bouncycastle.x509.CertPathReviewerException;
	using PKIXCertPathReviewer = org.bouncycastle.x509.PKIXCertPathReviewer;

	public class SignedMailValidator
	{
		private const string RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";

		private static readonly Class DEFAULT_CERT_PATH_REVIEWER = typeof(PKIXCertPathReviewer);

		private static readonly string EXT_KEY_USAGE = Extension.extendedKeyUsage.getId();

		private static readonly string SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();

		private const int shortKeyLength = 512;

		// (365.25*30)*24*3600*1000
		private static readonly long THIRTY_YEARS_IN_MILLI_SEC = 21915l * 12l * 3600l * 1000l;

		private static readonly JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

		private CertStore certs;

		private SignerInformationStore signers;

		private Map results;

		private string[] fromAddresses;

		private Class certPathReviewerClass;

		/// <summary>
		/// Validates the signed <seealso cref="MimeMessage"/> message. The
		/// <seealso cref="PKIXParameters"/> from param are used for the certificate path
		/// validation. The actual PKIXParameters used for the certificate path
		/// validation is a copy of param with the followin changes: <br> - The
		/// validation date is changed to the signature time <br> - A CertStore with
		/// certificates and crls from the mail message is added to the CertStores.<br>
		/// <br>
		/// In <code>param</code> it's also possible to add additional CertStores
		/// with intermediate Certificates and/or CRLs which then are also used for
		/// the validation.
		/// </summary>
		/// <param name="message"> the signed MimeMessage </param>
		/// <param name="param">   the parameters for the certificate path validation </param>
		/// <exception cref="SignedMailValidatorException"> if the message is no signed message or if an exception occurs
		/// reading the message </exception>
		public SignedMailValidator(MimeMessage message, PKIXParameters param) : this(message, param, DEFAULT_CERT_PATH_REVIEWER)
		{
		}

		/// <summary>
		/// Validates the signed <seealso cref="MimeMessage"/> message. The
		/// <seealso cref="PKIXParameters"/> from param are used for the certificate path
		/// validation. The actual PKIXParameters used for the certificate path
		/// validation is a copy of param with the followin changes: <br> - The
		/// validation date is changed to the signature time <br> - A CertStore with
		/// certificates and crls from the mail message is added to the CertStores.<br>
		/// <br>
		/// In <code>param</code> it's also possible to add additional CertStores
		/// with intermediate Certificates and/or CRLs which then are also used for
		/// the validation.
		/// </summary>
		/// <param name="message">               the signed MimeMessage </param>
		/// <param name="param">                 the parameters for the certificate path validation </param>
		/// <param name="certPathReviewerClass"> a subclass of <seealso cref="PKIXCertPathReviewer"/>. The SignedMailValidator
		///                              uses objects of this type for the cert path vailidation. The class must
		///                              have an empty constructor. </param>
		/// <exception cref="SignedMailValidatorException"> if the message is no signed message or if an exception occurs
		/// reading the message </exception>
		/// <exception cref="IllegalArgumentException"> if the certPathReviewerClass is not a
		/// subclass of <seealso cref="PKIXCertPathReviewer"/> or objects of
		/// certPathReviewerClass can not be instantiated </exception>
		public SignedMailValidator(MimeMessage message, PKIXParameters param, Class certPathReviewerClass)
		{
			this.certPathReviewerClass = certPathReviewerClass;
			bool isSubclass = DEFAULT_CERT_PATH_REVIEWER.isAssignableFrom(certPathReviewerClass);
			if (!isSubclass)
			{
				throw new IllegalArgumentException("certPathReviewerClass is not a subclass of " + DEFAULT_CERT_PATH_REVIEWER.getName());
			}

			SMIMESigned s;

			try
			{
				// check if message is multipart signed
				if (message.isMimeType("multipart/signed"))
				{
					MimeMultipart mimemp = (MimeMultipart)message.getContent();
					s = new SMIMESigned(mimemp);
				}
				else if (message.isMimeType("application/pkcs7-mime") || message.isMimeType("application/x-pkcs7-mime"))
				{
					s = new SMIMESigned(message);
				}
				else
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.noSignedMessage");
					throw new SignedMailValidatorException(msg);
				}

				// save certstore and signerInformationStore
				certs = (new JcaCertStoreBuilder()).addCertificates(s.getCertificates()).addCRLs(s.getCRLs()).setProvider("BC").build();
				signers = s.getSignerInfos();

				// save "from" addresses from message
				Address[] froms = message.getFrom();
				InternetAddress sender = null;
				try
				{
					if (message.getHeader("Sender") != null)
					{
						sender = new InternetAddress(message.getHeader("Sender")[0]);
					}
				}
				catch (MessagingException)
				{
					//ignore garbage in Sender: header
				}

				int fromsLength = (froms != null) ? froms.Length : 0;
				fromAddresses = new string[fromsLength + ((sender != null) ? 1 : 0)];
				for (int i = 0; i < fromsLength; i++)
				{
					InternetAddress inetAddr = (InternetAddress)froms[i];
					fromAddresses[i] = inetAddr.getAddress();
				}
				if (sender != null)
				{
					fromAddresses[fromsLength] = sender.getAddress();
				}

				// initialize results
				results = new HashMap();
			}
			catch (Exception e)
			{
				if (e is SignedMailValidatorException)
				{
					throw (SignedMailValidatorException)e;
				}
				// exception reading message
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.exceptionReadingMessage", new object[]{e.Message, e, e.GetType().getName()});
				throw new SignedMailValidatorException(msg, e);
			}

			// validate signatues
			validateSignatures(param);
		}

		public virtual void validateSignatures(PKIXParameters pkixParam)
		{
			PKIXParameters usedParameters = (PKIXParameters)pkixParam.clone();

			// add crls and certs from mail
			usedParameters.addCertStore(certs);

			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			// check each signer
			while (it.hasNext())
			{
				List errors = new ArrayList();
				List notifications = new ArrayList();

				SignerInformation signer = (SignerInformation)it.next();
				// signer certificate
				X509Certificate cert = null;

				try
				{
					Collection certCollection = findCerts(usedParameters.getCertStores(), selectorConverter.getCertSelector(signer.getSID()));

					Iterator certIt = certCollection.iterator();
					if (certIt.hasNext())
					{
						cert = (X509Certificate)certIt.next();
					}
				}
				catch (CertStoreException cse)
				{
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.exceptionRetrievingSignerCert", new object[]{cse.Message, cse, cse.GetType().getName()});
					errors.add(msg);
				}

				if (cert != null)
				{
					// check signature
					bool validSignature = false;
					try
					{
						validSignature = signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert.getPublicKey()));
						if (!validSignature)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.signatureNotVerified");
							errors.add(msg);
						}
					}
					catch (Exception e)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.exceptionVerifyingSignature", new object[]{e.Message, e, e.GetType().getName()});
						errors.add(msg);
					}

					// check signer certificate (mail address, key usage, etc)
					checkSignerCert(cert, errors, notifications);

					// notify if a signed receip request is in the message
					AttributeTable atab = signer.getSignedAttributes();
					if (atab != null)
					{
						Attribute attr = atab.get(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest);
						if (attr != null)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.signedReceiptRequest");
							notifications.add(msg);
						}
					}

					// check certificate path

					// get signing time if possible, otherwise use current time as
					// signing time
					DateTime signTime = getSignatureTime(signer);
					if (signTime == null) // no signing time was found
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.noSigningTime");
						notifications.add(msg);
						signTime = pkixParam.getDate();
						if (signTime == null)
						{
							signTime = DateTime.Now;
						}
					}
					else
					{
						// check if certificate was valid at signing time
						try
						{
							cert.checkValidity(signTime);
						}
						catch (CertificateExpiredException)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.certExpired", new object[]
							{
								new TrustedInput(signTime),
								new TrustedInput(cert.getNotAfter())
							});
							errors.add(msg);
						}
						catch (CertificateNotYetValidException)
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.certNotYetValid", new object[]
							{
								new TrustedInput(signTime),
								new TrustedInput(cert.getNotBefore())
							});
							errors.add(msg);
						}
					}
					usedParameters.setDate(signTime);

					try
					{
						// construct cert chain
						CertPath certPath;
						List userProvidedList;

						List userCertStores = new ArrayList();
						userCertStores.add(certs);
						object[] cpres = createCertPath(cert, usedParameters.getTrustAnchors(), pkixParam.getCertStores(), userCertStores);
						certPath = (CertPath)cpres[0];
						userProvidedList = (List)cpres[1];

						// validate cert chain
						PKIXCertPathReviewer review;
						try
						{
							review = (PKIXCertPathReviewer)certPathReviewerClass.newInstance();
						}
						catch (IllegalAccessException e)
						{
							throw new IllegalArgumentException("Cannot instantiate object of type " + certPathReviewerClass.getName() + ": " + e.Message);
						}
						catch (InstantiationException e)
						{
							throw new IllegalArgumentException("Cannot instantiate object of type " + certPathReviewerClass.getName() + ": " + e.Message);
						}
						review.init(certPath, usedParameters);
						if (!review.isValidCertPath())
						{
							ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.certPathInvalid");
							errors.add(msg);
						}
						results.put(signer, new ValidationResult(this, review, validSignature, errors, notifications, userProvidedList));
					}
					catch (GeneralSecurityException gse)
					{
						// cannot create cert path
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.exceptionCreateCertPath", new object[]{gse.Message, gse, gse.GetType().getName()});
						errors.add(msg);
						results.put(signer, new ValidationResult(this, null, validSignature, errors, notifications, null));
					}
					catch (CertPathReviewerException cpre)
					{
						// cannot initialize certpathreviewer - wrong parameters
						errors.add(cpre.getErrorMessage());
						results.put(signer, new ValidationResult(this, null, validSignature, errors, notifications, null));
					}
				}
				else
				{
				// no signer certificate found
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.noSignerCert");
					errors.add(msg);
					results.put(signer, new ValidationResult(this, null, false, errors, notifications, null));
				}
			}
		}

		public static Set getEmailAddresses(X509Certificate cert)
		{
			Set addresses = new HashSet();

			TBSCertificate tbsCertificate = getTBSCert(cert);

			RDN[] rdns = tbsCertificate.getSubject().getRDNs(PKCSObjectIdentifiers_Fields.pkcs_9_at_emailAddress);
			for (int i = 0; i < rdns.Length; i++)
			{
				AttributeTypeAndValue[] atVs = rdns[i].getTypesAndValues();

				for (int j = 0; j != atVs.Length; j++)
				{
					if (atVs[j].getType().Equals(PKCSObjectIdentifiers_Fields.pkcs_9_at_emailAddress))
					{
						string email = ((ASN1String)atVs[j].getValue()).getString().ToLower();
						addresses.add(email);
					}
				}
			}

			byte[] ext = cert.getExtensionValue(SUBJECT_ALTERNATIVE_NAME);
			if (ext != null)
			{
				ASN1Sequence altNames = ASN1Sequence.getInstance(getObject(ext));
				for (int j = 0; j < altNames.size(); j++)
				{
					ASN1TaggedObject o = (ASN1TaggedObject)altNames.getObjectAt(j);

					if (o.getTagNo() == 1)
					{
						string email = DERIA5String.getInstance(o, false).getString().ToLower();
						addresses.add(email);
					}
				}
			}

			return addresses;
		}

		private static ASN1Primitive getObject(byte[] ext)
		{
			ASN1InputStream aIn = new ASN1InputStream(ext);
			ASN1OctetString octs = (ASN1OctetString)aIn.readObject();

			aIn = new ASN1InputStream(octs.getOctets());
			return aIn.readObject();
		}

		public virtual void checkSignerCert(X509Certificate cert, List errors, List notifications)
		{
			// get key length
			PublicKey key = cert.getPublicKey();
			int keyLenght = -1;
			if (key is RSAPublicKey)
			{
				keyLenght = ((RSAPublicKey)key).getModulus().bitLength();
			}
			else if (key is DSAPublicKey)
			{
				keyLenght = ((DSAPublicKey)key).getParams().getP().bitLength();
			}
			if (keyLenght != -1 && keyLenght <= shortKeyLength)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.shortSigningKey", new object[]{Integers.valueOf(keyLenght)});
				notifications.add(msg);
			}

			// warn if certificate has very long validity period
			long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
			if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.longValidity", new object[]
				{
					new TrustedInput(cert.getNotBefore()),
					new TrustedInput(cert.getNotAfter())
				});
				notifications.add(msg);
			}

			// check key usage if digitalSignature or nonRepudiation is set
			bool[] keyUsage = cert.getKeyUsage();
			if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.signingNotPermitted");
				errors.add(msg);
			}

			// check extended key usage
			try
			{
				byte[] ext = cert.getExtensionValue(EXT_KEY_USAGE);
				if (ext != null)
				{
					ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage.getInstance(getObject(ext));
					if (!extKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage) && !extKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.extKeyUsageNotPermitted");
						errors.add(msg);
					}
				}
			}
			catch (Exception e)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.extKeyUsageError", new object[]{e.Message, e, e.GetType().getName()});
				errors.add(msg);
			}

			// cert has an email address
			try
			{
				Set certEmails = getEmailAddresses(cert);
				if (certEmails.isEmpty())
				{
					// error no email address in signing certificate
					ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.noEmailInCert");
					errors.add(msg);
				}
				else
				{
					// check if email in cert is equal to the from address in the
					// message
					bool equalsFrom = false;
					for (int i = 0; i < fromAddresses.Length; i++)
					{
						if (certEmails.contains(fromAddresses[i].ToLower()))
						{
							equalsFrom = true;
							break;
						}
					}
					if (!equalsFrom)
					{
						ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.emailFromCertMismatch", new object[]
						{
							new UntrustedInput(addressesToString(fromAddresses)),
							new UntrustedInput(certEmails)
						});
						errors.add(msg);
					}
				}
			}
			catch (Exception e)
			{
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.certGetEmailError", new object[]{e.Message, e, e.GetType().getName()});
				errors.add(msg);
			}
		}

		internal static string addressesToString(object[] a)
		{
			if (a == null)
			{
				return "null";
			}

			StringBuffer b = new StringBuffer();
			b.append('[');

			for (int i = 0; i != a.Length; i++)
			{
				if (i > 0)
				{
					b.append(", ");
				}
				b.append(a[i].ToString());
			}

			return b.append(']').ToString();
		}

		public static DateTime getSignatureTime(SignerInformation signer)
		{
			AttributeTable atab = signer.getSignedAttributes();
			DateTime result = null;
			if (atab != null)
			{
				Attribute attr = atab.get(CMSAttributes_Fields.signingTime);
				if (attr != null)
				{
					Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0).toASN1Primitive());
					result = t.getDate();
				}
			}
			return result;
		}

		private static List findCerts(List certStores, X509CertSelector selector)
		{
			List result = new ArrayList();
			Iterator it = certStores.iterator();
			while (it.hasNext())
			{
				CertStore store = (CertStore)it.next();
				Collection coll = store.getCertificates(selector);
				result.addAll(coll);
			}
			return result;
		}

		private static X509Certificate findNextCert(List certStores, X509CertSelector selector, Set certSet)
		{
			Iterator certIt = findCerts(certStores, selector).iterator();

			bool certFound = false;
			X509Certificate nextCert = null;
			while (certIt.hasNext())
			{
				nextCert = (X509Certificate)certIt.next();
				if (!certSet.contains(nextCert))
				{
					certFound = true;
					break;
				}
			}

			return certFound ? nextCert : null;
		}

		/// <param name="signerCert">   the end of the path </param>
		/// <param name="trustanchors"> trust anchors for the path </param>
		/// <param name="certStores"> </param>
		/// <returns> the resulting certificate path. </returns>
		/// <exception cref="GeneralSecurityException"> </exception>
		public static CertPath createCertPath(X509Certificate signerCert, Set trustanchors, List certStores)
		{
			object[] results = createCertPath(signerCert, trustanchors, certStores, null);
			return (CertPath)results[0];
		}

		/// <summary>
		/// Returns an Object array containing a CertPath and a List of Booleans. The list contains the value <code>true</code>
		/// if the corresponding certificate in the CertPath was taken from the user provided CertStores.
		/// </summary>
		/// <param name="signerCert">       the end of the path </param>
		/// <param name="trustanchors">     trust anchors for the path </param>
		/// <param name="systemCertStores"> list of <seealso cref="CertStore"/> provided by the system </param>
		/// <param name="userCertStores">   list of <seealso cref="CertStore"/> provided by the user </param>
		/// <returns> a CertPath and a List of booleans. </returns>
		/// <exception cref="GeneralSecurityException"> </exception>
		public static object[] createCertPath(X509Certificate signerCert, Set trustanchors, List systemCertStores, List userCertStores)
		{
			Set certSet = new LinkedHashSet();
			List userProvidedList = new ArrayList();

			// add signer certificate

			X509Certificate cert = signerCert;
			certSet.add(cert);
			userProvidedList.add(new bool?(true));

			bool trustAnchorFound = false;

			X509Certificate taCert = null;

			// add other certs to the cert path
			while (cert != null && !trustAnchorFound)
			{
				// check if cert Issuer is Trustanchor
				Iterator trustIt = trustanchors.iterator();
				while (trustIt.hasNext())
				{
					TrustAnchor anchor = (TrustAnchor)trustIt.next();
					X509Certificate anchorCert = anchor.getTrustedCert();
					if (anchorCert != null)
					{
						if (anchorCert.getSubjectX500Principal().Equals(cert.getIssuerX500Principal()))
						{
							try
							{
								cert.verify(anchorCert.getPublicKey(), "BC");
								trustAnchorFound = true;
								taCert = anchorCert;
								break;
							}
							catch (Exception)
							{
								// trustanchor not found
							}
						}
					}
					else
					{
						if (anchor.getCAName().Equals(cert.getIssuerX500Principal().getName()))
						{
							try
							{
								cert.verify(anchor.getCAPublicKey(), "BC");
								trustAnchorFound = true;
								break;
							}
							catch (Exception)
							{
								// trustanchor not found
							}
						}
					}
				}

				if (!trustAnchorFound)
				{
					// add next cert to path
					X509CertSelector select = new X509CertSelector();
					try
					{
						select.setSubject(cert.getIssuerX500Principal().getEncoded());
					}
					catch (IOException e)
					{
						throw new IllegalStateException(e.ToString());
					}
					byte[] authKeyIdentBytes = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
					if (authKeyIdentBytes != null)
					{
						try
						{
							AuthorityKeyIdentifier kid = AuthorityKeyIdentifier.getInstance(getObject(authKeyIdentBytes));
							if (kid.getKeyIdentifier() != null)
							{
								select.setSubjectKeyIdentifier((new DEROctetString(kid.getKeyIdentifier())).getEncoded(ASN1Encoding_Fields.DER));
							}
						}
						catch (IOException)
						{
							// ignore
						}
					}
					bool userProvided = false;

					cert = findNextCert(systemCertStores, select, certSet);
					if (cert == null && userCertStores != null)
					{
						userProvided = true;
						cert = findNextCert(userCertStores, select, certSet);
					}

					if (cert != null)
					{
						// cert found
						certSet.add(cert);
						userProvidedList.add(new bool?(userProvided));
					}
				}
			}

			// if a trustanchor was found - try to find a selfsigned certificate of
			// the trustanchor
			if (trustAnchorFound)
			{
				if (taCert != null && taCert.getSubjectX500Principal().Equals(taCert.getIssuerX500Principal()))
				{
					certSet.add(taCert);
					userProvidedList.add(new bool?(false));
				}
				else
				{
					X509CertSelector select = new X509CertSelector();

					try
					{
						select.setSubject(cert.getIssuerX500Principal().getEncoded());
						select.setIssuer(cert.getIssuerX500Principal().getEncoded());
					}
					catch (IOException e)
					{
						throw new IllegalStateException(e.ToString());
					}

					bool userProvided = false;

					taCert = findNextCert(systemCertStores, select, certSet);
					if (taCert == null && userCertStores != null)
					{
						userProvided = true;
						taCert = findNextCert(userCertStores, select, certSet);
					}
					if (taCert != null)
					{
						try
						{
							cert.verify(taCert.getPublicKey(), "BC");
							certSet.add(taCert);
							userProvidedList.add(new bool?(userProvided));
						}
						catch (GeneralSecurityException)
						{
							// wrong cert
						}
					}
				}
			}

			CertPath certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(new ArrayList(certSet));
			return new object[]{certPath, userProvidedList};
		}

		public virtual CertStore getCertsAndCRLs()
		{
			return certs;
		}

		public virtual SignerInformationStore getSignerInformationStore()
		{
			return signers;
		}

		public virtual ValidationResult getValidationResult(SignerInformation signer)
		{
			if (signers.getSigners(signer.getSID()).isEmpty())
			{
				// the signer is not part of the SignerInformationStore
				// he has not signed the message
				ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.wrongSigner");
				throw new SignedMailValidatorException(msg);
			}
			else
			{
				return (ValidationResult)results.get(signer);
			}
		}

		public class ValidationResult
		{
			private readonly SignedMailValidator outerInstance;


			internal PKIXCertPathReviewer review;

			internal List errors;

			internal List notifications;

			internal List userProvidedCerts;

			internal bool signVerified;

			public ValidationResult(SignedMailValidator outerInstance, PKIXCertPathReviewer review, bool verified, List errors, List notifications, List userProvidedCerts)
			{
				this.outerInstance = outerInstance;
				this.review = review;
				this.errors = errors;
				this.notifications = notifications;
				signVerified = verified;
				this.userProvidedCerts = userProvidedCerts;
			}

			/// <summary>
			/// Returns a list of error messages of type <seealso cref="ErrorBundle"/>.
			/// </summary>
			/// <returns> List of error messages </returns>
			public virtual List getErrors()
			{
				return errors;
			}

			/// <summary>
			/// Returns a list of notification messages of type <seealso cref="ErrorBundle"/>.
			/// </summary>
			/// <returns> List of notification messages </returns>
			public virtual List getNotifications()
			{
				return notifications;
			}

			/// <returns> the PKIXCertPathReviewer for the CertPath of this signature
			/// or null if an Exception occured. </returns>
			public virtual PKIXCertPathReviewer getCertPathReview()
			{
				return review;
			}

			/// <returns> the CertPath for this signature
			/// or null if an Exception occured. </returns>
			public virtual CertPath getCertPath()
			{
				return review != null ? review.getCertPath() : null;
			}

			/// <returns> a List of Booleans that are true if the corresponding certificate in the CertPath was taken from
			/// the CertStore of the SMIME message </returns>
			public virtual List getUserProvidedCerts()
			{
				return userProvidedCerts;
			}

			/// <returns> true if the signature corresponds to the public key of the
			/// signer </returns>
			public virtual bool isVerifiedSignature()
			{
				return signVerified;
			}

			/// <returns> true if the signature is valid (ie. if it corresponds to the
			/// public key of the signer and the cert path for the signers
			/// certificate is also valid) </returns>
			public virtual bool isValidSignature()
			{
				if (review != null)
				{
					return signVerified && review.isValidCertPath() && errors.isEmpty();
				}
				else
				{
					return false;
				}
			}
		}


		private static TBSCertificate getTBSCert(X509Certificate cert)
		{
			return TBSCertificate.getInstance(cert.getTBSCertificate());
		}
	}

}