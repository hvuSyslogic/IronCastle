namespace org.bouncycastle.mail.smime
{


	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedDataParser = org.bouncycastle.cms.CMSSignedDataParser;
	using CMSTypedStream = org.bouncycastle.cms.CMSTypedStream;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;

	/// <summary>
	/// general class for handling a pkcs7-signature message.
	/// <para>
	/// A simple example of usage - note, in the example below the validity of
	/// the certificate isn't verified, just the fact that one of the certs 
	/// matches the given signer...
	/// </para>
	/// <para>
	/// <pre>
	///  CertStore               certs = s.getCertificates("Collection", "BC");
	///  SignerInformationStore  signers = s.getSignerInfos();
	///  Collection              c = signers.getSigners();
	///  Iterator                it = c.iterator();
	/// 
	///  while (it.hasNext())
	///  {
	///      SignerInformation   signer = (SignerInformation)it.next();
	///      Collection          certCollection = certs.getCertificates(signer.getSID());
	/// 
	///      Iterator        certIt = certCollection.iterator();
	///      X509Certificate cert = (X509Certificate)certIt.next();
	/// 
	///      if (signer.verify(cert.getPublicKey()))
	///      {
	///          verified++;
	///      }   
	///  }
	/// </pre>
	/// </para>
	/// <para>
	/// Note: if you are using this class with AS2 or some other protocol
	/// that does not use 7bit as the default content transfer encoding you
	/// will need to use the constructor that allows you to specify the default
	/// content transfer encoding, such as "binary".
	/// </para>
	/// </summary>
	public class SMIMESignedParser : CMSSignedDataParser
	{
		internal object message;
		internal MimeBodyPart content;

		private static InputStream getInputStream(Part bodyPart)
		{
			try
			{
				if (bodyPart.isMimeType("multipart/signed"))
				{
					throw new MessagingException("attempt to create signed data object from multipart content - use MimeMultipart constructor.");
				}

				return bodyPart.getInputStream();
			}
			catch (IOException e)
			{
				throw new MessagingException("can't extract input stream: " + e);
			}
		}

		private static File getTmpFile()
		{
			try
			{
				return File.createTempFile("bcMail", ".mime");
			}
			catch (IOException e)
			{
				throw new MessagingException("can't extract input stream: " + e);
			}
		}

		private static CMSTypedStream getSignedInputStream(BodyPart bodyPart, string defaultContentTransferEncoding, File backingFile)
		{
			try
			{
				OutputStream @out = new BufferedOutputStream(new FileOutputStream(backingFile));

				SMIMEUtil.outputBodyPart(@out, true, bodyPart, defaultContentTransferEncoding);

				@out.close();

				InputStream @in = new TemporaryFileInputStream(backingFile);

				return new CMSTypedStream(@in);
			}
			catch (IOException e)
			{
				throw new MessagingException("can't extract input stream: " + e);
			}
		}

		static SMIMESignedParser()
		{
			CommandMap commandMap = CommandMap.getDefaultCommandMap();

			if (commandMap is MailcapCommandMap)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.activation.MailcapCommandMap mc = (javax.activation.MailcapCommandMap)commandMap;
				MailcapCommandMap mc = (MailcapCommandMap)commandMap;

				mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
				mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
				mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
				mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
				mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

				AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(mc));
			}
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private MailcapCommandMap mc;

			public PrivilegedActionAnonymousInnerClass(MailcapCommandMap mc)
			{
				this.mc = mc;
			}

			public object run()
			{
				CommandMap.setDefaultCommandMap(mc);

				return null;
			}
		}

		/// <summary>
		/// base constructor using a defaultContentTransferEncoding of 7bit. A temporary backing file
		/// will be created for the signed data.
		/// </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> signed message with signature. </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, MimeMultipart message) : this(digCalcProvider, message, getTmpFile())
		{
		}

		/// <summary>
		/// base constructor using a defaultContentTransferEncoding of 7bit and a specified backing file.
		/// </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> signed message with signature. </param>
		/// <param name="backingFile"> the temporary file to use to back the signed data. </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, MimeMultipart message, File backingFile) : this(digCalcProvider, message, "7bit", backingFile)
		{
		}

		/// <summary>
		/// base constructor with settable contentTransferEncoding. A temporary backing file will be created
		/// to contain the signed data.
		/// </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> the signed message with signature. </param>
		/// <param name="defaultContentTransferEncoding"> new default to use. </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs.r </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, MimeMultipart message, string defaultContentTransferEncoding) : this(digCalcProvider, message, defaultContentTransferEncoding, getTmpFile())
		{
		}

		/// <summary>
		/// base constructor with settable contentTransferEncoding and a specified backing file.
		/// </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> the signed message with signature. </param>
		/// <param name="defaultContentTransferEncoding"> new default to use. </param>
		/// <param name="backingFile"> the temporary file to use to back the signed data. </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, MimeMultipart message, string defaultContentTransferEncoding, File backingFile) : base(digCalcProvider, getSignedInputStream(message.getBodyPart(0), defaultContentTransferEncoding, backingFile), getInputStream(message.getBodyPart(1)))
		{

			this.message = message;
			this.content = (MimeBodyPart)message.getBodyPart(0);

			drainContent();
		}

		/// <summary>
		/// base constructor for a signed message with encapsulated content.
		/// <para>
		/// Note: in this case the encapsulated MimeBody part will only be suitable for a single
		/// writeTo - once writeTo has been called the file containing the body part will be deleted. If writeTo is not
		/// called the file will be left in the temp directory.
		/// </para> </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> the message containing the encapsulated signed data. </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="SMIMEException"> if the body part encapsulated in the message cannot be extracted. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, Part message) : base(digCalcProvider, getInputStream(message))
		{

			this.message = message;

			CMSTypedStream cont = this.getSignedContent();

			if (cont != null)
			{
				this.content = SMIMEUtil.toWriteOnceBodyPart(cont);
			}
		}

		/// <summary>
		/// Constructor for a signed message with encapsulated content. The encapsulated
		/// content, if it exists, is written to the file represented by the File object
		/// passed in.
		/// </summary>
		/// <param name="digCalcProvider"> provider for digest calculators. </param>
		/// <param name="message"> the Part containing the signed content. </param>
		/// <param name="file"> the file the encapsulated part is to be written to after it has been decoded.
		/// </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="SMIMEException"> if the body part encapsulated in the message cannot be extracted. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESignedParser(DigestCalculatorProvider digCalcProvider, Part message, File file) : base(digCalcProvider, getInputStream(message))
		{

			this.message = message;

			CMSTypedStream cont = this.getSignedContent();

			if (cont != null)
			{
				this.content = SMIMEUtil.toMimeBodyPart(cont, file);
			}
		}

		/// <summary>
		/// return the content that was signed. </summary>
		/// <returns> the signed body part in this message. </returns>
		public virtual MimeBodyPart getContent()
		{
			return content;
		}

		/// <summary>
		/// Return the content that was signed as a mime message.
		/// </summary>
		/// <param name="session"> the session to base the MimeMessage around. </param>
		/// <returns> a MimeMessage holding the content. </returns>
		/// <exception cref="MessagingException"> if there is an issue creating the MimeMessage. </exception>
		/// <exception cref="IOException"> if there is an issue reading the content. </exception>
		public virtual MimeMessage getContentAsMimeMessage(Session session)
		{
			if (message is MimeMultipart)
			{
				BodyPart bp = ((MimeMultipart)message).getBodyPart(0);
				return new MimeMessage(session, bp.getInputStream());
			}
			else
			{
				return new MimeMessage(session, getSignedContent().getContentStream());
			}
		}

		/// <summary>
		/// return the content that was signed with its signature attached. </summary>
		/// <returns> depending on whether this was unencapsulated or not it will return a MimeMultipart
		/// or a MimeBodyPart </returns>
		public virtual object getContentWithSignature()
		{
			return message;
		}

		private void drainContent()
		{
			try
			{
				this.getSignedContent().drain();
			}
			catch (IOException e)
			{
				throw new CMSException("unable to read content for verification: " + e, e);
			}
		}

		public class TemporaryFileInputStream : BufferedInputStream
		{
			internal readonly File _file;

			public TemporaryFileInputStream(File file) : base(new FileInputStream(file))
			{

				_file = file;
			}

			public virtual void close()
			{
				base.close();

				_file.delete();
			}
		}
	}

}