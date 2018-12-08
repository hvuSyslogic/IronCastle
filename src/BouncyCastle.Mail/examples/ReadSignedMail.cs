namespace org.bouncycastle.mail.smime.examples
{


	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// a simple example that reads a basic SMIME signed mail file.
	/// </summary>
	public class ReadSignedMail
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		/// <summary>
		/// verify the signature (assuming the cert is contained in the message)
		/// </summary>
		private static void verify(SMIMESigned s)
		{
			//
			// extract the information to verify the signatures.
			//

			//
			// certificates and crls passed in the signature
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

			MimeMessage msg = new MimeMessage(session, new FileInputStream("signed.message"));

			//
			// make sure this was a multipart/signed message - there should be
			// two parts as we have one part for the content that was signed and
			// one part for the actual signature.
			//
			if (msg.isMimeType("multipart/signed"))
			{
				SMIMESigned s = new SMIMESigned((MimeMultipart)msg.getContent());

				//
				// extract the content
				//
				MimeBodyPart content = s.getContent();

				JavaSystem.@out.println("Content:");

				object cont = content.getContent();

				if (cont is string)
				{
					JavaSystem.@out.println((string)cont);
				}
				else if (cont is Multipart)
				{
					Multipart mp = (Multipart)cont;
					int count = mp.getCount();
					for (int i = 0; i < count; i++)
					{
						BodyPart m = mp.getBodyPart(i);
						object part = m.getContent();

						JavaSystem.@out.println("Part " + i);
						JavaSystem.@out.println("---------------------------");

						if (part is string)
						{
							JavaSystem.@out.println((string)part);
						}
						else
						{
							JavaSystem.@out.println("can't print...");
						}
					}
				}

				JavaSystem.@out.println("Status:");

				verify(s);
			}
			else if (msg.isMimeType("application/pkcs7-mime") || msg.isMimeType("application/x-pkcs7-mime"))
			{
				//
				// in this case the content is wrapped in the signature block.
				//
				SMIMESigned s = new SMIMESigned(msg);

				//
				// extract the content
				//
				MimeBodyPart content = s.getContent();

				JavaSystem.@out.println("Content:");

				object cont = content.getContent();

				if (cont is string)
				{
					JavaSystem.@out.println((string)cont);
				}

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