using org.bouncycastle.mime.test;
using org.bouncycastle.util;

using System;

namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSException = org.bouncycastle.cms.CMSException;
	using OriginatorInformation = org.bouncycastle.cms.OriginatorInformation;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientId = org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using CMSTestUtil = org.bouncycastle.cms.test.CMSTestUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SMIMEEnvelopedWriter = org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
	using SMimeParserListener = org.bouncycastle.mime.smime.SMimeParserListener;
	using SMimeParserProvider = org.bouncycastle.mime.smime.SMimeParserProvider;
	using PEMKeyPair = org.bouncycastle.openssl.PEMKeyPair;
	using PEMParser = org.bouncycastle.openssl.PEMParser;
	using JcaPEMKeyConverter = org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Streams = org.bouncycastle.util.io.Streams;

	public class TestSMIMEEnveloped : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private static string _signDN;
		private static KeyPair _signKP;

		private static string _reciDN;
		private static KeyPair _reciKP;

		private static X509Certificate _reciCert;

		private static bool _initialised = false;

		private static readonly byte[] testMessage = Base64.decode("TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" + "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" + "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" + "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" + "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" + "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" + "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" + "wMTMyLS0NCg==");

		private static void init()
		{
			if (!_initialised)
			{
				if (Security.getProvider("BC") == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				_initialised = true;

				_signDN = "O=Bouncy Castle, C=AU";
				_signKP = CMSTestUtil.makeKeyPair();

				_reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
				_reciKP = CMSTestUtil.makeKeyPair();
				_reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
			}
		}

		public virtual void setUp()
		{
			init();
		}

		public virtual void testSMIMEEnveloped()
		{
			InputStream inputStream = this.GetType().getResourceAsStream("test256.message");

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(new ReadOnceInputStream(Streams.readAll(inputStream)));

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final TestDoneFlag dataParsed = new TestDoneFlag();
			TestDoneFlag dataParsed = new TestDoneFlag();

			p.parse(new SMimeParserListenerAnonymousInnerClass(this, dataParsed));

			assertTrue(dataParsed.isDone());
		}

		public class SMimeParserListenerAnonymousInnerClass : SMimeParserListener
		{
			private readonly TestSMIMEEnveloped outerInstance;

			private TestDoneFlag dataParsed;

			public SMimeParserListenerAnonymousInnerClass(TestSMIMEEnveloped outerInstance, TestDoneFlag dataParsed)
			{
				this.outerInstance = outerInstance;
				this.dataParsed = dataParsed;
			}

			public override void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
			{
				RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(outerInstance.loadCert("cert.pem")));

				assertNotNull(recipInfo);

				byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(outerInstance.loadKey("key.pem")));
				assertTrue(Arrays.areEqual(testMessage, content));

				dataParsed.markDone();
			}
		}

		public virtual void testKeyTransAES128()
		{
			//
			// output
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			SMIMEEnvelopedWriter.Builder envBldr = new SMIMEEnvelopedWriter.Builder();

			envBldr.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			SMIMEEnvelopedWriter envWrt = envBldr.build(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			OutputStream @out = envWrt.getContentStream();

			@out.write(testMessage);

			@out.close();

			//
			// parse
			//
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final TestDoneFlag dataParsed = new TestDoneFlag();
			TestDoneFlag dataParsed = new TestDoneFlag();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(new ReadOnceInputStream(bOut.toByteArray()));

			p.parse(new SMimeParserListenerAnonymousInnerClass2(this, dataParsed));

			assertTrue(dataParsed.isDone());
		}

		public class SMimeParserListenerAnonymousInnerClass2 : SMimeParserListener
		{
			private readonly TestSMIMEEnveloped outerInstance;

			private TestDoneFlag dataParsed;

			public SMimeParserListenerAnonymousInnerClass2(TestSMIMEEnveloped outerInstance, TestDoneFlag dataParsed)
			{
				this.outerInstance = outerInstance;
				this.dataParsed = dataParsed;
			}

			public override void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
			{
				RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(_reciCert));

				assertNotNull(recipInfo);

				byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()));
				assertTrue(Arrays.areEqual(testMessage, content));

				dataParsed.markDone();
			}
		}

		private X509Certificate loadCert(string name)
		{
			try
			{
				return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(this.GetType().getResourceAsStream(name));
			}
			catch (Exception e)
			{
				throw new IOException(e.Message);
			}
		}

		private PrivateKey loadKey(string name)
		{
			return (new JcaPEMKeyConverter()).setProvider("BC").getKeyPair((PEMKeyPair)(new PEMParser(new InputStreamReader(this.GetType().getResourceAsStream(name)))).readObject()).getPrivate();
		}
	}

}