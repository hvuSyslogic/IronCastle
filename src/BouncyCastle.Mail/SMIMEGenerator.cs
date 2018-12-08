using System;

namespace org.bouncycastle.mail.smime
{


	using CMSEnvelopedGenerator = org.bouncycastle.cms.CMSEnvelopedGenerator;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// super class of the various generators.
	/// </summary>
	public class SMIMEGenerator
	{
		private static Map BASE_CIPHER_NAMES = new HashMap();

		static SMIMEGenerator()
		{
			BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.DES_EDE3_CBC, "DESEDE");
			BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES128_CBC, "AES");
			BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES192_CBC, "AES");
			BASE_CIPHER_NAMES.put(CMSEnvelopedGenerator.AES256_CBC, "AES");
		}

		protected internal bool useBase64 = true;
		protected internal string encoding = "base64"; // default sets base64

		/// <summary>
		/// base constructor
		/// </summary>
		public SMIMEGenerator()
		{
		}

		/// <summary>
		/// set the content-transfer-encoding for the CMS block (enveloped data, signature, etc...)  in the message.
		/// </summary>
		/// <param name="encoding"> the encoding to use, default "base64", use "binary" for a binary encoding. </param>
		public virtual void setContentTransferEncoding(string encoding)
		{
			this.encoding = encoding;
			this.useBase64 = Strings.toLowerCase(encoding).Equals("base64");
		}

		/// <summary>
		/// Make sure we have a valid content body part - setting the headers
		/// with defaults if neccessary.
		/// </summary>
		public virtual MimeBodyPart makeContentBodyPart(MimeBodyPart content)
		{
			//
			// add the headers to the body part - if they are missing, in
			// the event they have already been set the content settings override
			// any defaults that might be set.
			//
			try
			{
				MimeMessage msg = new MimeMessage((Session)null);

				Enumeration e = content.getAllHeaders();

				msg.setDataHandler(content.getDataHandler());

				while (e.hasMoreElements())
				{
					Header hdr = (Header)e.nextElement();

					msg.setHeader(hdr.getName(), hdr.getValue());
				}

				msg.saveChanges();

				//
				// we do this to make sure at least the default headers are
				// set in the body part.
				//
				e = msg.getAllHeaders();

				while (e.hasMoreElements())
				{
					Header hdr = (Header)e.nextElement();

					if (Strings.toLowerCase(hdr.getName()).StartsWith("content-", StringComparison.Ordinal))
					{
						content.setHeader(hdr.getName(), hdr.getValue());
					}
				}
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception saving message state.", e);
			}

			return content;
		}

		/// <summary>
		/// extract an appropriate body part from the passed in MimeMessage
		/// </summary>
		public virtual MimeBodyPart makeContentBodyPart(MimeMessage message)
		{
			MimeBodyPart content = new MimeBodyPart();

			//
			// add the headers to the body part.
			//
			try
			{
				message.removeHeader("Message-Id");
				message.removeHeader("Mime-Version");

				// JavaMail has a habit of reparsing some content types, if the bodypart is
				// a multipart it might be signed, we rebuild the body part using the raw input stream for the message.
				try
				{
					if (message.getContent() is Multipart)
					{
						content.setContent(message.getRawInputStream(), message.getContentType());

						extractHeaders(content, message);

						return content;
					}
				}
				catch (MessagingException)
				{
					// fall back to usual method below
				}

				content.setContent(message.getContent(), message.getContentType());

				content.setDataHandler(message.getDataHandler());

				extractHeaders(content, message);
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception saving message state.", e);
			}
			catch (IOException e)
			{
				throw new SMIMEException("exception getting message content.", e);
			}

			return content;
		}

		private void extractHeaders(MimeBodyPart content, MimeMessage message)
		{
			Enumeration e = message.getAllHeaders();

			while (e.hasMoreElements())
			{
				Header hdr = (Header)e.nextElement();

				content.addHeader(hdr.getName(), hdr.getValue());
			}
		}

		public virtual KeyGenerator createSymmetricKeyGenerator(string encryptionOID, Provider provider)
		{
			try
			{
				return createKeyGenerator(encryptionOID, provider);
			}
			catch (NoSuchAlgorithmException e)
			{
				try
				{
					string algName = (string)BASE_CIPHER_NAMES.get(encryptionOID);
					if (!string.ReferenceEquals(algName, null))
					{
						return createKeyGenerator(algName, provider);
					}
				}
				catch (NoSuchAlgorithmException)
				{
					// ignore
				}
				if (provider != null)
				{
					return createSymmetricKeyGenerator(encryptionOID, null);
				}
				throw e;
			}
		}

		private KeyGenerator createKeyGenerator(string algName, Provider provider)
		{
			if (provider != null)
			{
				return KeyGenerator.getInstance(algName, provider);
			}
			else
			{
				return KeyGenerator.getInstance(algName);
			}
		}
	}

}