namespace org.bouncycastle.mail.smime.examples
{


	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

	/// <summary>
	/// a simple example that creates a single encrypted mail message.
	/// <para>
	/// The key store can be created using the class in
	/// org.bouncycastle.jce.examples.PKCS12Example - the program expects only one
	/// key to be present in the key file.
	/// </para>
	/// <para>
	/// Note: while this means that both the private key is available to
	/// the program, the private key is retrieved from the keystore only for
	/// the purposes of locating the corresponding public key, in normal circumstances
	/// you would only be doing this with a certificate available.
	/// </para>
	/// </summary>
	public class CreateLargeEncryptedMail
	{
		public static void Main(string[] args)
		{
			if (args.Length != 3)
			{
				JavaSystem.err.println("usage: CreateLargeEncryptedMail pkcs12Keystore password inputFile");
				System.exit(0);
			}

			//
			// Open the key store
			//
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			string keyAlias = ExampleUtils.findKeyAlias(ks, args[0], args[1].ToCharArray());

			Certificate[] chain = ks.getCertificateChain(keyAlias);

			//
			// create the generator for creating an smime/encrypted message
			//
			SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

			gen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator((X509Certificate)chain[0])).setProvider("BC"));

			//
			// create a subject key id - this has to be done the same way as
			// it is done in the certificate associated with the private key
			// version 3 only.
			//
			/*
			MessageDigest           dig = MessageDigest.getInstance("SHA1", "BC");
	
			dig.update(cert.getPublicKey().getEncoded());
			      
			gen.addKeyTransRecipient(cert.getPublicKey(), dig.digest());
			*/

			//
			// create the base for our message
			//
			MimeBodyPart msg = new MimeBodyPart();

			msg.setDataHandler(new DataHandler(new FileDataSource(new File(args[2]))));
			msg.setHeader("Content-Type", "application/octet-stream");
			msg.setHeader("Content-Transfer-Encoding", "binary");

			MimeBodyPart mp = gen.generate(msg, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC)).setProvider("BC").build());

			//
			// Get a Session object and create the mail message
			//
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example encrypted message");
			body.setContent(mp.getContent(), mp.getContentType());
			body.saveChanges();

			body.writeTo(new FileOutputStream("encrypted.message"));
		}
	}

}