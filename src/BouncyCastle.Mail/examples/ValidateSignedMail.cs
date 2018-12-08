using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.mail.smime.examples
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using JcaX509ExtensionUtils = org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SignedMailValidator = org.bouncycastle.mail.smime.validator.SignedMailValidator;
	using PKIXCertPathReviewer = org.bouncycastle.x509.PKIXCertPathReviewer;

	/// <summary>
	/// An Example that reads a signed mail and validates its signature. Also
	/// validating the certificate path from the signers key to a trusted entity
	/// </summary>
	public class ValidateSignedMail
	{

		/*
		 * Use trusted certificates from $JAVA_HOME/lib/security/cacerts as
		 * trustanchors
		 */
		public const bool useCaCerts = false;

		public static void Main(string[] args)
		{

			Security.addProvider(new BouncyCastleProvider());

			//
			// Get a Session object with the default properties.
			//
			Properties props = System.getProperties();

			Session session = Session.getDefaultInstance(props, null);

			// read message
			MimeMessage msg = new MimeMessage(session, new FileInputStream("signed.message"));

			// create PKIXparameters
			PKIXParameters param;

			if (useCaCerts)
			{
				KeyStore caCerts = KeyStore.getInstance("JKS");
				string javaHome = System.getProperty("java.home");
				caCerts.load(new FileInputStream(javaHome + "/lib/security/cacerts"), "changeit".ToCharArray());

				param = new PKIXParameters(caCerts);
			}
			else
			{
				// load trustanchors from files (here we only load one)
				Set trustanchors = new HashSet();
				TrustAnchor trust = getTrustAnchor("trustanchor");

				// create a dummy trustanchor if we can not find any trustanchor. so
				// we can still try to validate the message
				if (trust == null)
				{
					JavaSystem.@out.println("no trustanchor file found, using a dummy trustanchor");
					trust = getDummyTrustAnchor();
				}
				trustanchors.add(trust);

				param = new PKIXParameters(trustanchors);
			}

			// load one ore more crls from files (here we only load one crl)
			List crls = new ArrayList();
			X509CRL crl = loadCRL("crl.file");
			if (crl != null)
			{
				crls.add(crl);
			}
			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls), "BC");

			// add crls and enable revocation checking
			param.addCertStore(certStore);
			param.setRevocationEnabled(true);

			// or disable revocation checking
			// param.setRevocationEnabled(false);

			verifySignedMail(msg, param);
		}

		public const int TITLE = 0;
		public const int TEXT = 1;
		public const int SUMMARY = 2;
		public const int DETAIL = 3;

		internal static int dbgLvl = DETAIL;

		private const string RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";

		public static void verifySignedMail(MimeMessage msg, PKIXParameters param)
		{
			// set locale for the output
			Locale loc = Locale.ENGLISH;
			// Locale loc = Locale.GERMAN;

			// validate signatures
			SignedMailValidator validator = new SignedMailValidator(msg, param);

			// iterate over all signatures and print results
			Iterator it = validator.getSignerInformationStore().getSigners().iterator();
			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation) it.next();
				SignedMailValidator.ValidationResult result = validator.getValidationResult(signer);
				if (result.isValidSignature())
				{
					ErrorBundle errMsg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.sigValid");
					JavaSystem.@out.println(errMsg.getText(loc));
				}
				else
				{
					ErrorBundle errMsg = new ErrorBundle(RESOURCE_NAME, "SignedMailValidator.sigInvalid");
					JavaSystem.@out.println(errMsg.getText(loc));
					// print errors
					JavaSystem.@out.println("Errors:");
					Iterator errorsIt = result.getErrors().iterator();
					while (errorsIt.hasNext())
					{
						ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
						if (dbgLvl == DETAIL)
						{
							JavaSystem.@out.println("\t\t" + errorMsg.getDetail(loc));
						}
						else
						{
							JavaSystem.@out.println("\t\t" + errorMsg.getText(loc));
						}
					}
				}
				if (!result.getNotifications().isEmpty())
				{
					JavaSystem.@out.println("Notifications:");
					Iterator notIt = result.getNotifications().iterator();
					while (notIt.hasNext())
					{
						ErrorBundle notMsg = (ErrorBundle) notIt.next();
						if (dbgLvl == DETAIL)
						{
							JavaSystem.@out.println("\t\t" + notMsg.getDetail(loc));
						}
						else
						{
							JavaSystem.@out.println("\t\t" + notMsg.getText(loc));
						}
					}
				}
				PKIXCertPathReviewer review = result.getCertPathReview();
				if (review != null)
				{
					if (review.isValidCertPath())
					{
						JavaSystem.@out.println("Certificate path valid");
					}
					else
					{
						JavaSystem.@out.println("Certificate path invalid");
					}

					JavaSystem.@out.println("\nCertificate path validation results:");
					// global errors
					JavaSystem.@out.println("Errors:");
					Iterator errorsIt = review.getErrors(-1).iterator();
					while (errorsIt.hasNext())
					{
						ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
						if (dbgLvl == DETAIL)
						{
							JavaSystem.@out.println("\t\t" + errorMsg.getDetail(loc));
						}
						else
						{
							JavaSystem.@out.println("\t\t" + errorMsg.getText(loc));
						}
					}

					JavaSystem.@out.println("Notifications:");
					Iterator notificationsIt = review.getNotifications(-1).iterator();
					while (notificationsIt.hasNext())
					{
						ErrorBundle noteMsg = (ErrorBundle) notificationsIt.next();
						JavaSystem.@out.println("\t" + noteMsg.getText(loc));
					}

					// per certificate errors and notifications
					Iterator certIt = review.getCertPath().getCertificates().iterator();
					int i = 0;
					while (certIt.hasNext())
					{
						X509Certificate cert = (X509Certificate) certIt.next();
						JavaSystem.@out.println("\nCertificate " + i + "\n========");
						JavaSystem.@out.println("Issuer: " + cert.getIssuerDN().getName());
						JavaSystem.@out.println("Subject: " + cert.getSubjectDN().getName());

						// errors
						JavaSystem.@out.println("\tErrors:");
						errorsIt = review.getErrors(i).iterator();
						while (errorsIt.hasNext())
						{
							ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
							if (dbgLvl == DETAIL)
							{
								JavaSystem.@out.println("\t\t" + errorMsg.getDetail(loc));
							}
							else
							{
								JavaSystem.@out.println("\t\t" + errorMsg.getText(loc));
							}
						}

						// notifications
						JavaSystem.@out.println("\tNotifications:");
						notificationsIt = review.getNotifications(i).iterator();
						while (notificationsIt.hasNext())
						{
							ErrorBundle noteMsg = (ErrorBundle) notificationsIt.next();
							if (dbgLvl == DETAIL)
							{
								JavaSystem.@out.println("\t\t" + noteMsg.getDetail(loc));
							}
							else
							{
								JavaSystem.@out.println("\t\t" + noteMsg.getText(loc));
							}
						}

						i++;
					}
				}
			}

		}

		protected internal static TrustAnchor getTrustAnchor(string trustcert)
		{
			X509Certificate cert = loadCert(trustcert);
			if (cert != null)
			{
				byte[] ncBytes = cert.getExtensionValue(Extension.nameConstraints.getId());

				if (ncBytes != null)
				{
					ASN1Encodable extValue = JcaX509ExtensionUtils.parseExtensionValue(ncBytes);
					return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
				}
				return new TrustAnchor(cert, null);
			}
			return null;
		}

		protected internal static X509Certificate loadCert(string certfile)
		{
			X509Certificate cert = null;
			try
			{
				InputStream @in = new FileInputStream(certfile);

				CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
				cert = (X509Certificate) cf.generateCertificate(@in);
			}
			catch (Exception)
			{
				JavaSystem.@out.println(@"certfile """ + certfile + @""" not found - classpath is " + System.getProperty("java.class.path"));
			}
			return cert;
		}

		protected internal static X509CRL loadCRL(string crlfile)
		{
			X509CRL crl = null;
			try
			{
				InputStream @in = new FileInputStream(crlfile);

				CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
				crl = (X509CRL) cf.generateCRL(@in);
			}
			catch (Exception)
			{
				JavaSystem.@out.println(@"crlfile """ + crlfile + @""" not found - classpath is " + System.getProperty("java.class.path"));
			}
			return crl;
		}

		private static TrustAnchor getDummyTrustAnchor()
		{
			X500Principal principal = new X500Principal("CN=Dummy Trust Anchor");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(1024, new SecureRandom());
			PublicKey trustPubKey = kpg.generateKeyPair().getPublic();
			return new TrustAnchor(principal, trustPubKey, null);
		}

	}

}