namespace org.bouncycastle.mail.smime
{


	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using Recipient = org.bouncycastle.cms.Recipient;
	using RecipientId = org.bouncycastle.cms.RecipientId;
	using RecipientInfoGenerator = org.bouncycastle.cms.RecipientInfoGenerator;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using SignerId = org.bouncycastle.cms.SignerId;
	using SignerInfoGenerator = org.bouncycastle.cms.SignerInfoGenerator;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationVerifier = org.bouncycastle.cms.SignerInformationVerifier;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using CollectionStore = org.bouncycastle.util.CollectionStore;

	/// <summary>
	/// A tool kit of common tasks.
	/// </summary>
	public class SMIMEToolkit
	{
		private readonly DigestCalculatorProvider digestCalculatorProvider;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="digestCalculatorProvider">  provider for any digest calculations required. </param>
		public SMIMEToolkit(DigestCalculatorProvider digestCalculatorProvider)
		{
			this.digestCalculatorProvider = digestCalculatorProvider;
		}

		/// <summary>
		/// Return true if the passed in message (MimeBodyPart or MimeMessage) is encrypted.
		/// </summary>
		/// <param name="message"> message of interest </param>
		/// <returns> true if the message represents an encrypted message, false otherwise. </returns>
		/// <exception cref="MessagingException"> on a message processing issue. </exception>
		public virtual bool isEncrypted(Part message)
		{
			return message.getHeader("Content-Type")[0].Equals(@"application/pkcs7-mime; name=""smime.p7m""; smime-type=enveloped-data");
		}

		/// <summary>
		/// Return true if the passed in message (MimeBodyPart or MimeMessage) is a signed one.
		/// </summary>
		/// <param name="message"> message of interest </param>
		/// <returns> true if the message represents a signed message, false otherwise. </returns>
		/// <exception cref="MessagingException"> on a message processing issue. </exception>
		public virtual bool isSigned(Part message)
		{
			return message.getHeader("Content-Type")[0].StartsWith("multipart/signed") || message.getHeader("Content-Type")[0].Equals("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data");
		}

		/// <summary>
		/// Return true if the passed in MimeMultipart is a signed one.
		/// </summary>
		/// <param name="message"> message of interest </param>
		/// <returns>  true if the multipart has an attached signature, false otherwise. </returns>
		/// <exception cref="MessagingException"> on a message processing issue. </exception>
		public virtual bool isSigned(MimeMultipart message)
		{
			return message.getBodyPart(1).getHeader("Content-Type")[0].Equals("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
		}

		/// <summary>
		/// Return true if there is a signature on the message that can be verified by the verifier.
		/// </summary>
		/// <param name="message"> a MIME part representing a signed message. </param>
		/// <param name="verifier"> the verifier we want to find a signer for. </param>
		/// <returns> true if cert verifies message, false otherwise. </returns>
		/// <exception cref="SMIMEException"> on a SMIME handling issue. </exception>
		/// <exception cref="MessagingException"> on a basic message processing exception </exception>
		public virtual bool isValidSignature(Part message, SignerInformationVerifier verifier)
		{
			try
			{
				SMIMESignedParser s;

				if (message.isMimeType("multipart/signed"))
				{
					s = new SMIMESignedParser(digestCalculatorProvider, (MimeMultipart)message.getContent());
				}
				else
				{
					s = new SMIMESignedParser(digestCalculatorProvider, message);
				}

				return isAtLeastOneValidSigner(s, verifier);
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new SMIMEException("Parsing failure: " + e.Message, e);
			}
		}

		private bool isAtLeastOneValidSigner(SMIMESignedParser s, SignerInformationVerifier verifier)
		{
			if (verifier.hasAssociatedCertificate())
			{
				X509CertificateHolder cert = verifier.getAssociatedCertificate();
				SignerInformation signer = s.getSignerInfos().get(new SignerId(cert.getIssuer(), cert.getSerialNumber()));

				if (signer != null)
				{
					return signer.verify(verifier);
				}
			}

			Collection c = s.getSignerInfos().getSigners();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();

				if (signer.verify(verifier))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Return true if there is a signature on the message that can be verified by verifier..
		/// </summary>
		/// <param name="message"> a MIME part representing a signed message. </param>
		/// <param name="verifier"> the verifier we want to find a signer for. </param>
		/// <returns> true if cert verifies message, false otherwise. </returns>
		/// <exception cref="SMIMEException"> on a SMIME handling issue. </exception>
		/// <exception cref="MessagingException"> on a basic message processing exception </exception>
		public virtual bool isValidSignature(MimeMultipart message, SignerInformationVerifier verifier)
		{
			try
			{
				SMIMESignedParser s = new SMIMESignedParser(digestCalculatorProvider, message);

				return isAtLeastOneValidSigner(s, verifier);
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
		}


		/// <summary>
		/// Extract the signer's signing certificate from the message.
		/// </summary>
		/// <param name="message"> a MIME part/MIME message representing a signed message. </param>
		/// <param name="signerInformation"> the signer information identifying the signer of interest. </param>
		/// <returns> the signing certificate, null if not found. </returns>
		public virtual X509CertificateHolder extractCertificate(Part message, SignerInformation signerInformation)
		{
			try
			{
				SMIMESignedParser s;

				if (message is MimeMessage && message.isMimeType("multipart/signed"))
				{
					s = new SMIMESignedParser(digestCalculatorProvider, (MimeMultipart)message.getContent());
				}
				else
				{
					s = new SMIMESignedParser(digestCalculatorProvider, message);
				}

				Collection certCollection = s.getCertificates().getMatches(signerInformation.getSID());

				Iterator certIt = certCollection.iterator();
				if (certIt.hasNext())
				{
					return (X509CertificateHolder)certIt.next();
				}
				return null;
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new SMIMEException("Parsing failure: " + e.Message, e);
			}
		}

		/// <summary>
		/// Extract the signer's signing certificate from Multipart message content.
		/// </summary>
		/// <param name="message"> a MIME Multipart part representing a signed message. </param>
		/// <param name="signerInformation"> the signer information identifying the signer of interest. </param>
		/// <returns> the signing certificate, null if not found. </returns>
		public virtual X509CertificateHolder extractCertificate(MimeMultipart message, SignerInformation signerInformation)
		{
			try
			{
				SMIMESignedParser s = new SMIMESignedParser(digestCalculatorProvider, message);

				Collection certCollection = s.getCertificates().getMatches(signerInformation.getSID());

				Iterator certIt = certCollection.iterator();
				if (certIt.hasNext())
				{
					return (X509CertificateHolder)certIt.next();
				}
				return null;
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
		}

		/// <summary>
		/// Produce a signed message in multi-part format with the second part containing a detached signature for the first.
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <param name="signerInfoGenerator"> the generator to be used to generate the signature. </param>
		/// <returns> the resulting MimeMultipart </returns>
		/// <exception cref="SMIMEException"> on an exception calculating or creating the signed data. </exception>
		public virtual MimeMultipart sign(MimeBodyPart message, SignerInfoGenerator signerInfoGenerator)
		{
			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			if (signerInfoGenerator.hasAssociatedCertificate())
			{
				List certList = new ArrayList();

				certList.add(signerInfoGenerator.getAssociatedCertificate());

				gen.addCertificates(new CollectionStore(certList));
			}

			gen.addSignerInfoGenerator(signerInfoGenerator);

			return gen.generate(message);
		}

		/// <summary>
		/// Produce a signed message in encapsulated format where the message is encoded in the signature..
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <param name="signerInfoGenerator"> the generator to be used to generate the signature. </param>
		/// <returns> a BodyPart containing the encapsulated message. </returns>
		/// <exception cref="SMIMEException"> on an exception calculating or creating the signed data. </exception>
		public virtual MimeBodyPart signEncapsulated(MimeBodyPart message, SignerInfoGenerator signerInfoGenerator)
		{
			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			if (signerInfoGenerator.hasAssociatedCertificate())
			{
				List certList = new ArrayList();

				certList.add(signerInfoGenerator.getAssociatedCertificate());

				gen.addCertificates(new CollectionStore(certList));
			}

			gen.addSignerInfoGenerator(signerInfoGenerator);

			return gen.generateEncapsulated(message);
		}

		/// <summary>
		/// Encrypt the passed in MIME part returning a new encrypted MIME part.
		/// </summary>
		/// <param name="mimePart"> the part to be encrypted. </param>
		/// <param name="contentEncryptor"> the encryptor to use for the actual message content. </param>
		/// <param name="recipientGenerator">  the generator for the target recipient. </param>
		/// <returns> an encrypted MIME part. </returns>
		/// <exception cref="SMIMEException"> in the event of an exception creating the encrypted part. </exception>
		public virtual MimeBodyPart encrypt(MimeBodyPart mimePart, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
		{
			SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

			envGen.addRecipientInfoGenerator(recipientGenerator);

			return envGen.generate(mimePart, contentEncryptor);
		}

		/// <summary>
		/// Encrypt the passed in MIME multi-part returning a new encrypted MIME part.
		/// </summary>
		/// <param name="multiPart"> the multi-part to be encrypted. </param>
		/// <param name="contentEncryptor"> the encryptor to use for the actual message content. </param>
		/// <param name="recipientGenerator">  the generator for the target recipient. </param>
		/// <returns> an encrypted MIME part. </returns>
		/// <exception cref="SMIMEException"> in the event of an exception creating the encrypted part. </exception>
		public virtual MimeBodyPart encrypt(MimeMultipart multiPart, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
		{
			SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

			envGen.addRecipientInfoGenerator(recipientGenerator);

			MimeBodyPart bodyPart = new MimeBodyPart();

			bodyPart.setContent(multiPart);

			return envGen.generate(bodyPart, contentEncryptor);
		}

		/// <summary>
		/// Encrypt the passed in MIME message returning a new encrypted MIME part.
		/// </summary>
		/// <param name="message"> the multi-part to be encrypted. </param>
		/// <param name="contentEncryptor"> the encryptor to use for the actual message content. </param>
		/// <param name="recipientGenerator">  the generator for the target recipient. </param>
		/// <returns> an encrypted MIME part. </returns>
		/// <exception cref="SMIMEException"> in the event of an exception creating the encrypted part. </exception>
		public virtual MimeBodyPart encrypt(MimeMessage message, OutputEncryptor contentEncryptor, RecipientInfoGenerator recipientGenerator)
		{
			SMIMEEnvelopedGenerator envGen = new SMIMEEnvelopedGenerator();

			envGen.addRecipientInfoGenerator(recipientGenerator);

			return envGen.generate(message, contentEncryptor);
		}

		/// <summary>
		/// Decrypt the passed in MIME part returning a part representing the decrypted content.
		/// </summary>
		/// <param name="mimePart"> the part containing the encrypted data. </param>
		/// <param name="recipientId"> the recipient id in the date to be matched. </param>
		/// <param name="recipient"> the recipient to be used if a match is found. </param>
		/// <returns> a MIME part containing the decrypted content or null if the recipientId cannot be matched. </returns>
		/// <exception cref="SMIMEException"> on an exception doing the decryption. </exception>
		/// <exception cref="MessagingException"> on an exception parsing the message, </exception>
		public virtual MimeBodyPart decrypt(MimeBodyPart mimePart, RecipientId recipientId, Recipient recipient)
		{
			try
			{
				SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mimePart);

				RecipientInformationStore recipients = m.getRecipientInfos();
				RecipientInformation recipientInformation = recipients.get(recipientId);

				if (recipientInformation == null)
				{
					return null;
				}

				return SMIMEUtil.toMimeBodyPart(recipientInformation.getContent(recipient));
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new SMIMEException("Parsing failure: " + e.Message, e);
			}
		}

		/// <summary>
		/// Decrypt the passed in MIME message returning a part representing the decrypted content.
		/// </summary>
		/// <param name="message"> the message containing the encrypted data. </param>
		/// <param name="recipientId"> the recipient id in the date to be matched. </param>
		/// <param name="recipient"> the recipient to be used if a match is found. </param>
		/// <returns> a MIME part containing the decrypted content, or null if the recipientId cannot be matched. </returns>
		/// <exception cref="SMIMEException"> on an exception doing the decryption. </exception>
		/// <exception cref="MessagingException"> on an exception parsing the message, </exception>
		public virtual MimeBodyPart decrypt(MimeMessage message, RecipientId recipientId, Recipient recipient)
		{
			try
			{
				SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(message);

				RecipientInformationStore recipients = m.getRecipientInfos();
				RecipientInformation recipientInformation = recipients.get(recipientId);

				if (recipientInformation == null)
				{
					return null;
				}

				return SMIMEUtil.toMimeBodyPart(recipientInformation.getContent(recipient));
			}
			catch (CMSException e)
			{
				throw new SMIMEException("CMS processing failure: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new SMIMEException("Parsing failure: " + e.Message, e);
			}
		}
	}

}