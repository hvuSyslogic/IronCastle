namespace org.bouncycastle.mail.smime.examples
{


	using RecipientId = org.bouncycastle.cms.RecipientId;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientId = org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;

	/// <summary>
	/// a simple example that reads an encrypted email.
	/// <para>
	/// The key store can be created using the class in
	/// org.bouncycastle.jce.examples.PKCS12Example - the program expects only one
	/// key to be present.
	/// </para>
	/// </summary>
	public class ReadEncryptedMail
	{
		public static void Main(string[] args)
		{
			if (args.Length != 2)
			{
				JavaSystem.err.println("usage: ReadEncryptedMail pkcs12Keystore password");
				System.exit(0);
			}

			//
			// Open the key store
			//
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

			ks.load(new FileInputStream(args[0]), args[1].ToCharArray());

			Enumeration e = ks.aliases();
			string keyAlias = null;

			while (e.hasMoreElements())
			{
				string alias = (string)e.nextElement();

				if (ks.isKeyEntry(alias))
				{
					keyAlias = alias;
				}
			}

			if (string.ReferenceEquals(keyAlias, null))
			{
				JavaSystem.err.println("can't find a private key!");
				System.exit(0);
			}

			//
			// find the certificate for the private key and generate a 
			// suitable recipient identifier.
			//
			X509Certificate cert = (X509Certificate)ks.getCertificate(keyAlias);
			RecipientId recId = new JceKeyTransRecipientId(cert);

			//
			// Get a Session object with the default properties.
			//         
			Properties props = System.getProperties();

			Session session = Session.getDefaultInstance(props, null);

			MimeMessage msg = new MimeMessage(session, new FileInputStream("encrypted.message"));

			SMIMEEnveloped m = new SMIMEEnveloped(msg);

			RecipientInformationStore recipients = m.getRecipientInfos();
			RecipientInformation recipient = recipients.get(recId);

			MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent((new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, null))).setProvider("BC")));

			JavaSystem.@out.println("Message Contents");
			JavaSystem.@out.println("----------------");
			JavaSystem.@out.println(res.getContent());
		}
	}

}