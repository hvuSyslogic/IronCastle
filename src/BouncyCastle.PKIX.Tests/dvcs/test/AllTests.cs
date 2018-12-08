namespace org.bouncycastle.dvcs.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using CertEtcToken = org.bouncycastle.asn1.dvcs.CertEtcToken;
	using TargetEtcChain = org.bouncycastle.asn1.dvcs.TargetEtcChain;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using CMSSignedDataGenerator = org.bouncycastle.cms.CMSSignedDataGenerator;
	using SignerId = org.bouncycastle.cms.SignerId;
	using SignerInformationVerifier = org.bouncycastle.cms.SignerInformationVerifier;
	using SignerInformationVerifierProvider = org.bouncycastle.cms.SignerInformationVerifierProvider;
	using JcaSignerInfoGeneratorBuilder = org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using CMSTestUtil = org.bouncycastle.cms.test.CMSTestUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public class AllTests : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private static bool initialised = false;

		private static string origDN;
		private static KeyPair origKP;
		private static X509Certificate origCert;

		private static string signDN;
		private static KeyPair signKP;
		private static X509Certificate signCert;

		private static void init()
		{
			if (!initialised)
			{
				initialised = true;

				if (Security.getProvider(BC) == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}
				origDN = "O=Bouncy Castle, C=AU";
				origKP = CMSTestUtil.makeKeyPair();
				origCert = CMSTestUtil.makeCertificate(origKP, origDN, origKP, origDN);

				signDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
				signKP = CMSTestUtil.makeKeyPair();
				signCert = CMSTestUtil.makeCertificate(signKP, signDN, origKP, origDN);
			}
		}

		public virtual void setUp()
		{
			init();
		}

		private byte[] getInput(string name)
		{
			return Streams.readAll(this.GetType().getResourceAsStream(name));
		}

		public virtual void testCCPDRequest()
		{
			SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

			CCPDRequestBuilder reqBuilder = new CCPDRequestBuilder();

			MessageImprintBuilder imprintBuilder = new MessageImprintBuilder(new SHA1DigestCalculator());

			MessageImprint messageImprint = imprintBuilder.build(new byte[100]);

			CMSSignedData reqMsg = gen.build(reqBuilder.build(messageImprint));

			assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProviderAnonymousInnerClass(this)));

			DVCSRequest request = new DVCSRequest(reqMsg);

			CCPDRequestData reqData = (CCPDRequestData)request.getData();

			assertEquals(messageImprint, reqData.getMessageImprint());
		}

		public class SignerInformationVerifierProviderAnonymousInnerClass : SignerInformationVerifierProvider
		{
			private readonly AllTests outerInstance;

			public SignerInformationVerifierProviderAnonymousInnerClass(AllTests outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public SignerInformationVerifier get(SignerId sid)
			{
				return (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(signCert);
			}
		}

		private CMSSignedData getWrappedCPDRequest()
		{
			SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

			CPDRequestBuilder reqBuilder = new CPDRequestBuilder();

			return gen.build(reqBuilder.build(new byte[100]));
		}

		public virtual void testCPDRequest()
		{
			CMSSignedData reqMsg = getWrappedCPDRequest();

			assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProviderAnonymousInnerClass2(this)));

			DVCSRequest request = new DVCSRequest(reqMsg);

			CPDRequestData reqData = (CPDRequestData)request.getData();

			assertTrue(Arrays.areEqual(new byte[100], reqData.getMessage()));
		}

		public class SignerInformationVerifierProviderAnonymousInnerClass2 : SignerInformationVerifierProvider
		{
			private readonly AllTests outerInstance;

			public SignerInformationVerifierProviderAnonymousInnerClass2(AllTests outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public SignerInformationVerifier get(SignerId sid)
			{
				return (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(signCert);
			}
		}

		public virtual void testVPKCRequest()
		{
			SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

			VPKCRequestBuilder reqBuilder = new VPKCRequestBuilder();

			reqBuilder.addTargetChain(new JcaX509CertificateHolder(signCert));

			CMSSignedData reqMsg = gen.build(reqBuilder.build());

			assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProviderAnonymousInnerClass3(this)));

			DVCSRequest request = new DVCSRequest(reqMsg);

			VPKCRequestData reqData = (VPKCRequestData)request.getData();

			assertEquals(new TargetEtcChain(new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, (new JcaX509CertificateHolder(signCert)).toASN1Structure())), ((TargetChain)reqData.getCerts().get(0)).toASN1Structure());
		}

		public class SignerInformationVerifierProviderAnonymousInnerClass3 : SignerInformationVerifierProvider
		{
			private readonly AllTests outerInstance;

			public SignerInformationVerifierProviderAnonymousInnerClass3(AllTests outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public SignerInformationVerifier get(SignerId sid)
			{
				return (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(signCert);
			}
		}

		public virtual void testVSDRequest()
		{
			CMSSignedData message = getWrappedCPDRequest();

			SignedDVCSMessageGenerator gen = getSignedDVCSMessageGenerator();

			VSDRequestBuilder reqBuilder = new VSDRequestBuilder();

			CMSSignedData reqMsg = gen.build(reqBuilder.build(message));

			assertTrue(reqMsg.verifySignatures(new SignerInformationVerifierProviderAnonymousInnerClass4(this)));

			DVCSRequest request = new DVCSRequest(reqMsg);

			VSDRequestData reqData = (VSDRequestData)request.getData();

			assertEquals(message.toASN1Structure().getContentType(), reqData.getParsedMessage().toASN1Structure().getContentType());
		}

		public class SignerInformationVerifierProviderAnonymousInnerClass4 : SignerInformationVerifierProvider
		{
			private readonly AllTests outerInstance;

			public SignerInformationVerifierProviderAnonymousInnerClass4(AllTests outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public SignerInformationVerifier get(SignerId sid)
			{
				return (new JcaSimpleSignerInfoVerifierBuilder()).setProvider(BC).build(signCert);
			}
		}

		private SignedDVCSMessageGenerator getSignedDVCSMessageGenerator()
		{
			CMSSignedDataGenerator sigDataGen = new CMSSignedDataGenerator();

			JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = (new JcaDigestCalculatorProviderBuilder()).setProvider(BC);

			ContentSigner contentSigner = (new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(signKP.getPrivate());

			sigDataGen.addSignerInfoGenerator((new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build())).build(contentSigner, signCert));

			return new SignedDVCSMessageGenerator(sigDataGen);
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			junit.textui.TestRunner.run(suite());
		}

		public static Test suite()
		{
			TestSuite suite = new TestSuite("EAC tests");

			suite.addTestSuite(typeof(AllTests));
			suite.addTestSuite(typeof(DVCSParseTest));

			return new DVCSTestSetup(suite);
		}
	}

}