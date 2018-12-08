namespace org.bouncycastle.mail.smime
{


	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessable = org.bouncycastle.cms.CMSProcessable;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;

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
	public class SMIMESigned : CMSSignedData
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

		static SMIMESigned()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.activation.MailcapCommandMap mc = (javax.activation.MailcapCommandMap)javax.activation.CommandMap.getDefaultCommandMap();
			MailcapCommandMap mc = (MailcapCommandMap)CommandMap.getDefaultCommandMap();

			mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(mc));
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
		/// base constructor using a defaultContentTransferEncoding of 7bit
		/// </summary>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESigned(MimeMultipart message) : base(new CMSProcessableBodyPartInbound(message.getBodyPart(0)), getInputStream(message.getBodyPart(1)))
		{

			this.message = message;
			this.content = (MimeBodyPart)message.getBodyPart(0);
		}

		/// <summary>
		/// base constructor with settable contentTransferEncoding
		/// </summary>
		/// <param name="message"> the signed message </param>
		/// <param name="defaultContentTransferEncoding"> new default to use </param>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESigned(MimeMultipart message, string defaultContentTransferEncoding) : base(new CMSProcessableBodyPartInbound(message.getBodyPart(0), defaultContentTransferEncoding), getInputStream(message.getBodyPart(1)))
		{

			this.message = message;
			this.content = (MimeBodyPart)message.getBodyPart(0);
		}

		/// <summary>
		/// base constructor for a signed message with encapsulated content.
		/// </summary>
		/// <exception cref="MessagingException"> on an error extracting the signature or
		/// otherwise processing the message. </exception>
		/// <exception cref="SMIMEException"> if the body part encapsulated in the message cannot be extracted. </exception>
		/// <exception cref="CMSException"> if some other problem occurs. </exception>
		public SMIMESigned(Part message) : base(getInputStream(message))
		{

			this.message = message;

			CMSProcessable cont = this.getSignedContent();

			if (cont != null)
			{
				byte[] contBytes = (byte[])cont.getContent();

				this.content = SMIMEUtil.toMimeBodyPart(contBytes);
			}
		}

		/// <summary>
		/// return the content that was signed.
		/// </summary>
		public virtual MimeBodyPart getContent()
		{
			return content;
		}

		/// <summary>
		/// Return the content that was signed as a mime message.
		/// </summary>
		/// <param name="session"> </param>
		/// <returns> a MimeMessage holding the content. </returns>
		/// <exception cref="MessagingException"> </exception>
		public virtual MimeMessage getContentAsMimeMessage(Session session)
		{
			object content = getSignedContent().getContent();
			byte[] contentBytes = null;

			if (content is byte[])
			{
				contentBytes = (byte[])content;
			}
			else if (content is MimePart)
			{
				MimePart part = (MimePart)content;
				ByteArrayOutputStream @out;

				if (part.getSize() > 0)
				{
					@out = new ByteArrayOutputStream(part.getSize());
				}
				else
				{
					@out = new ByteArrayOutputStream();
				}

				part.writeTo(@out);
				contentBytes = @out.toByteArray();
			}
			else
			{
				string type = "<null>";
				if (content != null)
				{
					type = content.GetType().getName();
				}

				throw new MessagingException("Could not transfrom content of type " + type + " into MimeMessage.");
			}

			if (contentBytes != null)
			{
				ByteArrayInputStream @in = new ByteArrayInputStream(contentBytes);

				return new MimeMessage(session, @in);
			}

			return null;
		}

		/// <summary>
		/// return the content that was signed - depending on whether this was
		/// unencapsulated or not it will return a MimeMultipart or a MimeBodyPart
		/// </summary>
		public virtual object getContentWithSignature()
		{
			return message;
		}
	}

}