namespace org.bouncycastle.mail.smime.examples
{


	using RecipientId = org.bouncycastle.cms.RecipientId;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientId = org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
	using SharedFileInputStream = org.bouncycastle.mail.smime.util.SharedFileInputStream;

	/// <summary>
	/// a simple example that reads an encrypted email using the large file model.
	/// <para>
	/// The key store can be created using the class in
	/// org.bouncycastle.jce.examples.PKCS12Example - the program expects only one
	/// key to be present.
	/// </para>
	/// </summary>
	public class ReadLargeEncryptedMail
	{
		public static void Main(string[] args)
		{
			if (args.Length != 3)
			{
				JavaSystem.err.println("usage: ReadLargeEncryptedMail pkcs12Keystore password outputFile");
				System.exit(0);
			}

			//
			// Open the key store
			//
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			string keyAlias = ExampleUtils.findKeyAlias(ks, args[0], args[1].ToCharArray());

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

			MimeMessage msg = new MimeMessage(session, new SharedFileInputStream("encrypted.message"));

			SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(msg);

			RecipientInformationStore recipients = m.getRecipientInfos();
			RecipientInformation recipient = recipients.get(recId);

			MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream((new JceKeyTransEnvelopedRecipient((PrivateKey)ks.getKey(keyAlias, null))).setProvider("BC")));

			ExampleUtils.dumpContent(res, args[2]);
		}
	}

}