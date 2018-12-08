using org.bouncycastle.mime.test;
using org.bouncycastle.util;

namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSignerId = org.bouncycastle.cms.jcajce.JcaSignerId;
	using JcaSimpleSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using CMSTestUtil = org.bouncycastle.cms.test.CMSTestUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SMIMESignedWriter = org.bouncycastle.mime.smime.SMIMESignedWriter;
	using SMimeParserListener = org.bouncycastle.mime.smime.SMimeParserListener;
	using SMimeParserProvider = org.bouncycastle.mime.smime.SMimeParserProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using Store = org.bouncycastle.util.Store;
	using Strings = org.bouncycastle.util.Strings;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Streams = org.bouncycastle.util.io.Streams;

	public class TestSMIMESigned : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private static string _signDN;
		private static KeyPair _signKP;

		private static string _reciDN;
		private static KeyPair _reciKP;

		private static X509Certificate _signCert;
		private static X509Certificate _reciCert;

		private static bool _initialised = false;

		private static readonly byte[] simpleMessage = Strings.toByteArray("Content-Type: text/plain; name=null; charset=us-ascii\r\n" + "Content-Transfer-Encoding: 7bit\r\n" + "Content-Disposition: inline; filename=null\r\n" + "\r\n" + "Hello, world!\r\n");

		private static readonly byte[] simpleMessageContent = Strings.toByteArray("Hello, world!\r\n");

		private static readonly byte[] testMultipartMessage = Base64.decode("TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" + "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" + "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" + "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" + "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" + "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" + "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" + "wMTMyLS0NCg==");

		private static readonly byte[] testMultipartMessageContent = Base64.decode("LS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzINCkNvbnRlbnQtVHlwZTogdGV4dC9w" + "bGFpbjsgbmFtZT1udWxsOyBjaGFyc2V0PXVzLWFzY2lpDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5n" + "OiA3Yml0DQpDb250ZW50LURpc3Bvc2l0aW9uOiBpbmxpbmU7IGZpbGVuYW1lPW51bGwNCg0KQ2lhbyBm" + "cm9tIHZpZW5uYQ0KLS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzItLQ0K");

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
				_signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

				_reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
				_reciKP = CMSTestUtil.makeKeyPair();
				_reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
			}
		}

		public virtual void setUp()
		{
			init();
		}

		public virtual void testSimpleGeneration()
		{
			generationTest(simpleMessage, simpleMessageContent);
		}

		public virtual void testEmbeddedMultipartGeneration()
		{
			generationTest(testMultipartMessage, testMultipartMessageContent);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private void generationTest(byte[] message, final byte[] messageContent) throws Exception
		private void generationTest(byte[] message, byte[] messageContent)
		{
			//
			// output
			//
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			SMIMESignedWriter.Builder sigBldr = new SMIMESignedWriter.Builder();

			sigBldr.addCertificate(new JcaX509CertificateHolder(_signCert));

			sigBldr.addSignerInfoGenerator((new JcaSimpleSignerInfoGeneratorBuilder()).setProvider(BC).build("SHA256withRSA", _signKP.getPrivate(), _signCert));

			SMIMESignedWriter sigWrt = sigBldr.build(bOut);

			OutputStream @out = sigWrt.getContentStream();

			@out.write(message);

			@out.close();

			//
			// parse
			//
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final TestDoneFlag dataParsed = new TestDoneFlag();
			TestDoneFlag dataParsed = new TestDoneFlag();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(new ReadOnceInputStream(bOut.toByteArray()));

			p.parse(new SMimeParserListenerAnonymousInnerClass(this, messageContent, dataParsed));

			assertTrue(dataParsed.isDone());
		}

		public class SMimeParserListenerAnonymousInnerClass : SMimeParserListener
		{
			private readonly TestSMIMESigned outerInstance;

			private byte[] messageContent;
			private TestDoneFlag dataParsed;

			public SMimeParserListenerAnonymousInnerClass(TestSMIMESigned outerInstance, byte[] messageContent, TestDoneFlag dataParsed)
			{
				this.outerInstance = outerInstance;
				this.messageContent = messageContent;
				this.dataParsed = dataParsed;
			}

			public override void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{
				byte[] content = Streams.readAll(inputStream);

				assertTrue(Arrays.areEqual(messageContent, content));
			}

			public override void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
			{
				SignerInformation signerInfo = signers.get(new JcaSignerId(_signCert));

				assertNotNull(signerInfo);

				Collection certCollection = certificates.getMatches(signerInfo.getSID());

				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

				try
				{
					assertEquals(true, signerInfo.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException(e.Message, e);
				}
				catch (CertificateException e)
				{
					throw new CMSException(e.Message, e);
				}

				dataParsed.markDone();
			}
		}
	}

}