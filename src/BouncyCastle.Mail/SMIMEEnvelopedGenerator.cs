using System;

namespace org.bouncycastle.mail.smime
{


	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSEnvelopedDataGenerator = org.bouncycastle.cms.CMSEnvelopedDataGenerator;
	using CMSEnvelopedDataStreamGenerator = org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using RecipientInfoGenerator = org.bouncycastle.cms.RecipientInfoGenerator;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// General class for generating a pkcs7-mime message.
	/// 
	/// A simple example of usage.
	/// 
	/// <pre>
	///      SMIMEEnvelopedGenerator  fact = new SMIMEEnvelopedGenerator();
	/// 
	///      fact.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
	/// 
	///      MimeBodyPart mp = fact.generate(content, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());
	/// </pre>
	/// 
	/// <b>Note:</b> Most clients expect the MimeBodyPart to be in a MimeMultipart
	/// when it's sent.
	/// </summary>
	public class SMIMEEnvelopedGenerator : SMIMEGenerator
	{
		public static readonly string DES_EDE3_CBC = CMSEnvelopedDataGenerator.DES_EDE3_CBC;
		public static readonly string RC2_CBC = CMSEnvelopedDataGenerator.RC2_CBC;
		public const string IDEA_CBC = CMSEnvelopedDataGenerator.IDEA_CBC;
		public const string CAST5_CBC = CMSEnvelopedDataGenerator.CAST5_CBC;

		public static readonly string AES128_CBC = CMSEnvelopedDataGenerator.AES128_CBC;
		public static readonly string AES192_CBC = CMSEnvelopedDataGenerator.AES192_CBC;
		public static readonly string AES256_CBC = CMSEnvelopedDataGenerator.AES256_CBC;

		public static readonly string CAMELLIA128_CBC = CMSEnvelopedDataGenerator.CAMELLIA128_CBC;
		public static readonly string CAMELLIA192_CBC = CMSEnvelopedDataGenerator.CAMELLIA192_CBC;
		public static readonly string CAMELLIA256_CBC = CMSEnvelopedDataGenerator.CAMELLIA256_CBC;

		public static readonly string SEED_CBC = CMSEnvelopedDataGenerator.SEED_CBC;

		public static readonly string DES_EDE3_WRAP = CMSEnvelopedDataGenerator.DES_EDE3_WRAP;
		public static readonly string AES128_WRAP = CMSEnvelopedDataGenerator.AES128_WRAP;
		public static readonly string AES256_WRAP = CMSEnvelopedDataGenerator.AES256_WRAP;
		public static readonly string CAMELLIA128_WRAP = CMSEnvelopedDataGenerator.CAMELLIA128_WRAP;
		public static readonly string CAMELLIA192_WRAP = CMSEnvelopedDataGenerator.CAMELLIA192_WRAP;
		public static readonly string CAMELLIA256_WRAP = CMSEnvelopedDataGenerator.CAMELLIA256_WRAP;
		public static readonly string SEED_WRAP = CMSEnvelopedDataGenerator.SEED_WRAP;

		public static readonly string ECDH_SHA1KDF = CMSEnvelopedDataGenerator.ECDH_SHA1KDF;

		private const string ENCRYPTED_CONTENT_TYPE = @"application/pkcs7-mime; name=""smime.p7m""; smime-type=enveloped-data";

		private EnvelopedGenerator fact;
		private List recipients = new ArrayList();

		static SMIMEEnvelopedGenerator()
		{
			AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass());
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			public object run()
			{
				CommandMap commandMap = CommandMap.getDefaultCommandMap();

				if (commandMap is MailcapCommandMap)
				{
					CommandMap.setDefaultCommandMap(addCommands((MailcapCommandMap)commandMap));
				}

				return null;
			}
		}

		private static MailcapCommandMap addCommands(MailcapCommandMap mc)
		{
			mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			return mc;
		}

		/// <summary>
		/// base constructor
		/// </summary>
		public SMIMEEnvelopedGenerator()
		{
			fact = new EnvelopedGenerator(this);
		}

		/// <summary>
		/// add a recipientInfoGenerator.
		/// </summary>
		public virtual void addRecipientInfoGenerator(RecipientInfoGenerator recipientInfoGen)
		{
			fact.addRecipientInfoGenerator(recipientInfoGen);
		}

		/// <summary>
		/// Use a BER Set to store the recipient information
		/// </summary>
		public virtual void setBerEncodeRecipients(bool berEncodeRecipientSet)
		{
			fact.setBEREncodeRecipients(berEncodeRecipientSet);
		}

		 /// <summary>
		 /// if we get here we expect the Mime body part to be well defined.
		 /// </summary>
		private MimeBodyPart make(MimeBodyPart content, OutputEncryptor encryptor)
		{
			try
			{
				MimeBodyPart data = new MimeBodyPart();

				data.setContent(new ContentEncryptor(this, content, encryptor), ENCRYPTED_CONTENT_TYPE);
				data.addHeader("Content-Type", ENCRYPTED_CONTENT_TYPE);
				data.addHeader("Content-Disposition", @"attachment; filename=""smime.p7m""");
				data.addHeader("Content-Description", "S/MIME Encrypted Message");
				data.addHeader("Content-Transfer-Encoding", encoding);

				return data;
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception putting multi-part together.", e);
			}
		}

		/// <summary>
		/// generate an enveloped object that contains an SMIME Enveloped
		/// object using the given content encryptor
		/// </summary>
		public virtual MimeBodyPart generate(MimeBodyPart content, OutputEncryptor encryptor)
		{
			return make(makeContentBodyPart(content), encryptor);
		}

		/// <summary>
		/// generate an enveloped object that contains an SMIME Enveloped
		/// object using the given provider from the contents of the passed in
		/// message
		/// </summary>
		public virtual MimeBodyPart generate(MimeMessage message, OutputEncryptor encryptor)
		{
			try
			{
				message.saveChanges(); // make sure we're up to date.
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("unable to save message", e);
			}

			return make(makeContentBodyPart(message), encryptor);
		}

		public class ContentEncryptor : SMIMEStreamingProcessor
		{
			private readonly SMIMEEnvelopedGenerator outerInstance;

			internal readonly MimeBodyPart _content;
			internal OutputEncryptor _encryptor;

			internal bool _firstTime = true;

			public ContentEncryptor(SMIMEEnvelopedGenerator outerInstance, MimeBodyPart content, OutputEncryptor encryptor)
			{
				this.outerInstance = outerInstance;
				_content = content;
				_encryptor = encryptor;
			}

			public virtual void write(OutputStream @out)
			{
				OutputStream encrypted;

				try
				{
					if (_firstTime)
					{
						encrypted = outerInstance.fact.open(@out, _encryptor);

						_firstTime = false;
					}
					else
					{
						encrypted = outerInstance.fact.regenerate(@out, _encryptor);
					}

					CommandMap commandMap = CommandMap.getDefaultCommandMap();

					if (commandMap is MailcapCommandMap)
					{
						_content.getDataHandler().setCommandMap(addCommands((MailcapCommandMap)commandMap));
					}

					_content.writeTo(encrypted);

					encrypted.close();
				}
				catch (MessagingException e)
				{
					throw new WrappingIOException(e.ToString(), e);
				}
				catch (CMSException e)
				{
					throw new WrappingIOException(e.ToString(), e);
				}
			}
		}

		public class EnvelopedGenerator : CMSEnvelopedDataStreamGenerator
		{
			private readonly SMIMEEnvelopedGenerator outerInstance;

			public EnvelopedGenerator(SMIMEEnvelopedGenerator outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			internal ASN1ObjectIdentifier dataType;
			internal ASN1EncodableVector recipientInfos;

			public override OutputStream open(ASN1ObjectIdentifier dataType, OutputStream @out, ASN1EncodableVector recipientInfos, OutputEncryptor encryptor)
			{
				this.dataType = dataType;
				this.recipientInfos = recipientInfos;

				return base.open(dataType, @out, recipientInfos, encryptor);
			}

			public virtual OutputStream regenerate(OutputStream @out, OutputEncryptor encryptor)
			{
				return base.open(dataType, @out, recipientInfos, encryptor);
			}
		}

		public class WrappingIOException : IOException
		{
			internal Exception cause;

			public WrappingIOException(string msg, Exception cause) : base(msg)
			{

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}