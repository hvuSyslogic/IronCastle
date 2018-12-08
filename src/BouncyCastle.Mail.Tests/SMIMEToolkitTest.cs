using org.bouncycastle.asn1.nist;

using System;

namespace org.bouncycastle.mail.smime.test
{


	using Assert = junit.framework.Assert;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using JcaCertStore = org.bouncycastle.cert.jcajce.JcaCertStore;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSException = org.bouncycastle.cms.CMSException;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientId = org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaPKIXIdentityBuilder = org.bouncycastle.openssl.jcajce.JcaPKIXIdentityBuilder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using JcaPKIXIdentity = org.bouncycastle.pkix.jcajce.JcaPKIXIdentity;
	using CollectionStore = org.bouncycastle.util.CollectionStore;
	using Store = org.bouncycastle.util.Store;

	public class SMIMEToolkitTest : TestCase
	{

		internal static MimeBodyPart msg;

		internal static MimeBodyPart msgR;
		internal static MimeBodyPart msgRN;

		internal static string _origDN;
		internal static KeyPair _origKP;
		internal static X509Certificate _origCert;

		internal static string _signDN;
		internal static KeyPair _signKP;
		internal static X509Certificate _signCert;

		internal static string _reciDN;
		internal static KeyPair _reciKP;
		internal static X509Certificate _reciCert;

		private static KeyPair _signGostKP;
		private static X509Certificate _signGostCert;

		private static KeyPair _signEcDsaKP;
		private static X509Certificate _signEcDsaCert;

		private static KeyPair _signEcGostKP;
		private static X509Certificate _signEcGostCert;

		internal KeyPair dsaSignKP;
		internal X509Certificate dsaSignCert;

		internal KeyPair dsaOrigKP;
		internal X509Certificate dsaOrigCert;
		private const string BC = "BC";

		static SMIMEToolkitTest()
		{
			try
			{
				if (Security.getProvider("BC") == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				msg = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");

				msgR = SMIMETestUtil.makeMimeBodyPart("Hello world!\r");
				msgRN = SMIMETestUtil.makeMimeBodyPart("Hello world!\r\n");

				_origDN = "O=Bouncy Castle, C=AU";
				_origKP = CMSTestUtil.makeKeyPair();
				_origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

				_signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
				_signKP = CMSTestUtil.makeKeyPair();
				_signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

				_signGostKP = CMSTestUtil.makeGostKeyPair();
				_signGostCert = CMSTestUtil.makeCertificate(_signGostKP, _signDN, _origKP, _origDN);

				_signEcDsaKP = CMSTestUtil.makeEcDsaKeyPair();
				_signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

				_signEcGostKP = CMSTestUtil.makeEcGostKeyPair();
				_signEcGostCert = CMSTestUtil.makeCertificate(_signEcGostKP, _signDN, _origKP, _origDN);

				_reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
				_reciKP = CMSTestUtil.makeKeyPair();
				_reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
			}
			catch (Exception e)
			{
				throw new RuntimeException("problem setting up signed test class: " + e);
			}
		}

		public virtual void testSignedMessageRecognitionMultipart()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

			Assert.assertTrue(toolkit.isSigned(smm));

			MimeMessage body = makeMimeMessage(smm);

			Assert.assertTrue(toolkit.isSigned(body));
		}

		public virtual void testSignedMessageRecognitionEncapsulated()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = generateEncapsulated();

			Assert.assertTrue(toolkit.isSigned(res));

			MimeMessage body = makeMimeMessage(res);

			Assert.assertTrue(toolkit.isSigned(body));
		}

		public virtual void testEncryptedRecognition()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());
			MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

			SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

			gen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			MimeBodyPart res = gen.generate(msg, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());

			Assert.assertTrue(toolkit.isEncrypted(res));

			MimeMessage body = makeMimeMessage(res);

			Assert.assertTrue(toolkit.isEncrypted(body));
		}

		public virtual void testCertificateExtractionEncapsulated()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = generateEncapsulated();

			SMIMESigned smimeSigned = new SMIMESigned(res);

			SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

			assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(res, signerInformation));

			MimeMessage body = makeMimeMessage(res);

			assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(body, signerInformation));
		}

		public virtual void testCertificateExtractionMultipart()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

			SMIMESigned smimeSigned = new SMIMESigned(smm);

			SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

			assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(smm, signerInformation));

			MimeMessage body = makeMimeMessage(smm);

			assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(body, signerInformation));
		}

		public virtual void testSignedMessageVerificationMultipart()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

			Assert.assertTrue(toolkit.isValidSignature(smm, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));

			MimeMessage body = makeMimeMessage(smm);

			Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));
		}

		public virtual void testSignedMessageVerificationEncapsulated()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = generateEncapsulated();

			Assert.assertTrue(toolkit.isValidSignature(res, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));

			MimeMessage body = makeMimeMessage(res);

			Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));
		}

		public virtual void testSignedMessageVerificationEncapsulatedWithPKIXIdentity()
		{
			JcaPKIXIdentity identity = openIdentityResource("smimeTKkey.pem", "smimeTKcert.pem");

			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			List certList = new ArrayList();

			certList.add(identity.getCertificate());

			Store certs = new CollectionStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA1withRSA", identity.getPrivateKey(), identity.getX509Certificate()));

			gen.addCertificates(certs);

			MimeBodyPart res = gen.generateEncapsulated(msg);

			Assert.assertTrue(toolkit.isValidSignature(res, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(identity.getCertificate())));

			MimeMessage body = makeMimeMessage(res);

			Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(identity.getCertificate())));
			Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(identity.getX509Certificate())));
		}

		public virtual void testEncryptedMimeBodyPart()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = toolkit.encrypt(msg, (new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes128_CBC)).setProvider(BC).build(), (new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			Assert.assertTrue(toolkit.isEncrypted(res));

			MimeBodyPart dec = toolkit.decrypt(res, new JceKeyTransRecipientId(_reciCert), (new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

			SMIMETestUtil.verifyMessageBytes(msg, dec);
		}

		public virtual void testEncryptedMimeBodyPartWithPKIXIdentity()
		{
			JcaPKIXIdentity identity = openIdentityResource("smimeTKkey.pem", "smimeTKcert.pem");

			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = toolkit.encrypt(msg, (new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes128_CBC)).setProvider(BC).build(), (new JceKeyTransRecipientInfoGenerator(identity.getX509Certificate())).setProvider(BC));

			Assert.assertTrue(toolkit.isEncrypted(res));

			MimeBodyPart dec = toolkit.decrypt(res, identity.getRecipientId(), (new JceKeyTransEnvelopedRecipient(identity.getPrivateKey())).setProvider(BC));

			SMIMETestUtil.verifyMessageBytes(msg, dec);
		}

		public virtual void testEncryptedMessage()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeMessage message = makeMimeMessage(msg);
			MimeBodyPart res = toolkit.encrypt(message, (new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes128_CBC)).setProvider(BC).build(), (new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			Assert.assertTrue(toolkit.isEncrypted(res));

			MimeMessage body = makeMimeMessage(res);

			MimeBodyPart dec = toolkit.decrypt(body, new JceKeyTransRecipientId(_reciCert), (new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

			SMIMETestUtil.verifyMessageBytes(message, dec);
		}

		public virtual void testEncryptedSignedMultipart()
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeBodyPart res = signEncrypt(msg, _signKP.getPrivate(), _signCert, _reciCert);

			Assert.assertTrue(toolkit.isEncrypted(res));

			MimeMessage body = makeMimeMessage(res);

			MimeBodyPart dec = toolkit.decrypt(body, new JceKeyTransRecipientId(_reciCert), (new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

			Assert.assertTrue(toolkit.isSigned(dec));

			Assert.assertTrue(toolkit.isValidSignature(dec, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));

			SMIMETestUtil.verifyMessageBytes(msg, (MimeBodyPart)((MimeMultipart)dec.getContent()).getBodyPart(0));
		}

		private MimeBodyPart signEncrypt(MimeBodyPart msg, PrivateKey signerKey, X509Certificate signerCert, X509Certificate recipientCert)
		{
			SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			MimeMultipart smm = toolkit.sign(msg, (new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA1withRSA", signerKey, signerCert));

			return toolkit.encrypt(smm, (new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers_Fields.id_aes128_CBC)).setProvider(BC).build(), (new JceKeyTransRecipientInfoGenerator(recipientCert)).setProvider(BC));
		}

		public virtual void testSignedMessageGenerationMultipart()
		{
			 SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			 MimeMultipart smm = toolkit.sign(msg, (new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

			 Assert.assertTrue(toolkit.isValidSignature(smm, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));

			 SMIMESigned smimeSigned = new SMIMESigned(smm);

			 SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

			 assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(smm, signerInformation));

			 Properties props = System.getProperties();
			 Session session = Session.getDefaultInstance(props, null);

			 Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			 Address toUser = new InternetAddress("example@bouncycastle.org");

			 MimeMessage body = new MimeMessage(session);
			 body.setFrom(fromUser);
			 body.setRecipient(Message.RecipientType.TO, toUser);
			 body.setSubject("example signed message");
			 body.setContent(smm, smm.getContentType());
			 body.saveChanges();

			 Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));
		}

		 public virtual void testSignedMessageGenerationEncapsulated()
		 {
			 SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

			 MimeBodyPart res = toolkit.signEncapsulated(msg, (new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

			 Assert.assertTrue(toolkit.isValidSignature(res, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));

			 SMIMESigned smimeSigned = new SMIMESigned(res);

			 SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

			 assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(res, signerInformation));

			 Properties props = System.getProperties();
			 Session session = Session.getDefaultInstance(props, null);

			 Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			 Address toUser = new InternetAddress("example@bouncycastle.org");

			 MimeMessage body = new MimeMessage(session);
			 body.setFrom(fromUser);
			 body.setRecipient(Message.RecipientType.TO, toUser);
			 body.setSubject("example signed message");
			 body.setContent(res.getContent(), res.getContentType());
			 body.saveChanges();

			 Assert.assertTrue(toolkit.isValidSignature(body, (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(_signCert)));
		 }

		private MimeMultipart generateMultiPartRsa(string algorithm, MimeBodyPart msg, Map micalgs)
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator(micalgs);

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build(algorithm, _signKP.getPrivate(), _signCert));
			gen.addCertificates(certs);

			return gen.generate(msg);
		}

		private MimeMessage makeMimeMessage(MimeBodyPart res)
		{
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example message");
			body.setContent(res.getContent(), res.getContentType());
			body.saveChanges();

			return body;
		}

		private MimeMessage makeMimeMessage(MimeMultipart mm)
		{
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example message");
			body.setContent(mm, mm.getContentType());
			body.saveChanges();

			return body;
		}

		private MimeBodyPart generateEncapsulated()
		{
			List certList = new ArrayList();

			certList.add(_signCert);
			certList.add(_origCert);

			Store certs = new JcaCertStore(certList);

			SMIMESignedGenerator gen = new SMIMESignedGenerator();

			gen.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

			gen.addCertificates(certs);

			return gen.generateEncapsulated(msg);
		}

		private JcaPKIXIdentity openIdentityResource(string keyFileName, string certFileName)
		{
			InputStream keyRes = this.GetType().getResourceAsStream(keyFileName);
			InputStream certRes = this.GetType().getResourceAsStream(certFileName);

			return (new JcaPKIXIdentityBuilder()).setProvider(BC).build(keyRes, certRes);
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(SMIMEToolkitTest));
		}

		public static Test suite()
		{
			return new SMIMETestSetup(new TestSuite(typeof(SMIMEToolkitTest)));
		}
	}

}