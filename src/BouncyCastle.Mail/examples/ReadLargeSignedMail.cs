namespace org.bouncycastle.mail.smime.examples
{


	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SharedFileInputStream = org.bouncycastle.mail.smime.util.SharedFileInputStream;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// a simple example that reads a basic SMIME signed mail file.
	/// </summary>
	public class ReadLargeSignedMail
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		/// <summary>
		/// verify the signature (assuming the cert is contained in the message)
		/// </summary>
		private static void verify(SMIMESignedParser s)
		{
			//
			// extract the information to verify the signatures.
			//

			//
			// certificates and crls passed in the signature - this must happen before
			// s.getSignerInfos()
			//
			Store certs = s.getCertificates();

			//
			// SignerInfo blocks which contain the signatures
			//
			SignerInformationStore signers = s.getSignerInfos();

			Collection c = signers.getSigners();
			Iterator it = c.iterator();

			//
			// check each signer
			//
			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				Collection certCollection = certs.getMatches(signer.getSID());

				Iterator certIt = certCollection.iterator();
				X509Certificate cert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate((X509CertificateHolder)certIt.next());


				//
				// verify that the sig is correct and that it was generated
				// when the certificate was current
				//
				if (signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(cert)))
				{
					JavaSystem.@out.println("signature verified");
				}
				else
				{
					JavaSystem.@out.println("signature failed!");
				}
			}
		}

		public static void Main(string[] args)
		{
			//
			// Get a Session object with the default properties.
			//         
			Properties props = System.getProperties();

			Session session = Session.getDefaultInstance(props, null);

			MimeMessage msg = new MimeMessage(session, new SharedFileInputStream("signed.message"));

			//
			// make sure this was a multipart/signed message - there should be
			// two parts as we have one part for the content that was signed and
			// one part for the actual signature.
			//
			if (msg.isMimeType("multipart/signed"))
			{
				SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).build(), (MimeMultipart)msg.getContent());

				JavaSystem.@out.println("Status:");

				verify(s);
			}
			else if (msg.isMimeType("application/pkcs7-mime"))
			{
				//
				// in this case the content is wrapped in the signature block.
				//
				SMIMESignedParser s = new SMIMESignedParser((new JcaDigestCalculatorProviderBuilder()).build(), msg);

				JavaSystem.@out.println("Status:");

				verify(s);
			}
			else
			{
				JavaSystem.err.println("Not a signed message!");
			}
		}
	}

}