using System;

namespace org.bouncycastle.cert.cmp.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using CMPCertificate = org.bouncycastle.asn1.cmp.CMPCertificate;
	using CertConfirmContent = org.bouncycastle.asn1.cmp.CertConfirmContent;
	using CertOrEncCert = org.bouncycastle.asn1.cmp.CertOrEncCert;
	using CertRepMessage = org.bouncycastle.asn1.cmp.CertRepMessage;
	using CertResponse = org.bouncycastle.asn1.cmp.CertResponse;
	using CertifiedKeyPair = org.bouncycastle.asn1.cmp.CertifiedKeyPair;
	using PKIBody = org.bouncycastle.asn1.cmp.PKIBody;
	using PKIMessage = org.bouncycastle.asn1.cmp.PKIMessage;
	using PKIStatus = org.bouncycastle.asn1.cmp.PKIStatus;
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using CertReqMessages = org.bouncycastle.asn1.crmf.CertReqMessages;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using ProofOfPossession = org.bouncycastle.asn1.crmf.ProofOfPossession;
	using SubsequentMessage = org.bouncycastle.asn1.crmf.SubsequentMessage;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using CertificateRequestMessage = org.bouncycastle.cert.crmf.CertificateRequestMessage;
	using CertificateRequestMessageBuilder = org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
	using PKMACBuilder = org.bouncycastle.cert.crmf.PKMACBuilder;
	using JcaCertificateRequestMessageBuilder = org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
	using JcaEncryptedValueBuilder = org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
	using JceCRMFEncryptorBuilder = org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
	using JcePKMACValuesCalculator = org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaX509v3CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using AsymmetricKeyUnwrapper = org.bouncycastle.@operator.AsymmetricKeyUnwrapper;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;
	using JceAsymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyWrapper;
	using JceInputDecryptorProviderBuilder = org.bouncycastle.@operator.jcajce.JceInputDecryptorProviderBuilder;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public class AllTests : TestCase
	{
		private static readonly byte[] TEST_DATA = "Hello world!".getBytes();
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;
		private const string TEST_DATA_HOME = "bc.test.data.home";

		/*
		 *
		 *  INFRASTRUCTURE
		 *
		 */

		public AllTests(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(AllTests));
		}

		public static Test suite()
		{
			return new TestSuite(typeof(AllTests));
		}

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		public virtual void tearDown()
		{

		}

		public virtual void testProtectedMessage()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

			GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
			GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

			ContentSigner signer = (new JcaContentSignerBuilder("MD5WithRSAEncryption")).setProvider(BC).build(kp.getPrivate());
			ProtectedPKIMessage message = (new ProtectedPKIMessageBuilder(sender, recipient)).setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence())))).addCMPCertificate(cert).build(signer);

			X509Certificate jcaCert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate(message.getCertificates()[0]);
			ContentVerifierProvider verifierProvider = (new JcaContentVerifierProviderBuilder()).setProvider(BC).build(jcaCert.getPublicKey());

			assertTrue(message.verify(verifierProvider));

			assertEquals(sender, message.getHeader().getSender());
			assertEquals(recipient, message.getHeader().getRecipient());
		}

		public virtual void testMacProtectedMessage()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

			GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
			GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

			ProtectedPKIMessage message = (new ProtectedPKIMessageBuilder(sender, recipient)).setBody(new PKIBody(PKIBody.TYPE_INIT_REP, CertRepMessage.getInstance(new DERSequence(new DERSequence())))).addCMPCertificate(cert).build((new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC))).build("secret".ToCharArray()));

			PKMACBuilder pkMacBuilder = new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC));

			assertTrue(message.verify(pkMacBuilder, "secret".ToCharArray()));

			assertEquals(sender, message.getHeader().getSender());
			assertEquals(recipient, message.getHeader().getRecipient());
		}

		public virtual void testConfirmationMessage()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

			GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
			GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

			CertificateConfirmationContent content = (new CertificateConfirmationContentBuilder()).addAcceptedCertificate(cert, BigInteger.valueOf(1)).build((new JcaDigestCalculatorProviderBuilder()).build());

			ContentSigner signer = (new JcaContentSignerBuilder("MD5WithRSAEncryption")).setProvider(BC).build(kp.getPrivate());
			ProtectedPKIMessage message = (new ProtectedPKIMessageBuilder(sender, recipient)).setBody(new PKIBody(PKIBody.TYPE_CERT_CONFIRM, content.toASN1Structure())).addCMPCertificate(cert).build(signer);

			X509Certificate jcaCert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate(message.getCertificates()[0]);
			ContentVerifierProvider verifierProvider = (new JcaContentVerifierProviderBuilder()).setProvider(BC).build(jcaCert.getPublicKey());

			assertTrue(message.verify(verifierProvider));

			assertEquals(sender, message.getHeader().getSender());
			assertEquals(recipient, message.getHeader().getRecipient());

			content = new CertificateConfirmationContent(CertConfirmContent.getInstance(message.getBody().getContent()));

			CertificateStatus[] statusList = content.getStatusMessages();

			assertEquals(1, statusList.Length);
			assertTrue(statusList[0].isVerified(cert, (new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build()));
		}

		public virtual void testSampleCr()
		{
			PKIMessage msg = loadMessage("sample_cr.der");
			ProtectedPKIMessage procMsg = new ProtectedPKIMessage(new GeneralPKIMessage(msg));

			assertTrue(procMsg.verify(new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC)), "TopSecret1234".ToCharArray()));
		}

		public virtual void testSubsequentMessage()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

			ContentSigner signer = (new JcaContentSignerBuilder("SHA256withRSA")).setProvider(BC).build(kp.getPrivate());

			GeneralName user = new GeneralName(new X500Name("CN=Test"));

			CertificateRequestMessageBuilder builder = (new JcaCertificateRequestMessageBuilder(BigInteger.valueOf(1))).setPublicKey(kp.getPublic()).setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

					ProtectedPKIMessage certRequestMsg = (new ProtectedPKIMessageBuilder(user, user)).setTransactionID(new byte[] {1, 2, 3, 4, 5}).setBody(new PKIBody(PKIBody.TYPE_KEY_UPDATE_REQ, new CertReqMessages(builder.build().toASN1Structure()))).addCMPCertificate(cert).build(signer);

			ProtectedPKIMessage msg = new ProtectedPKIMessage(new GeneralPKIMessage(certRequestMsg.toASN1Structure().getEncoded()));

			CertReqMessages reqMsgs = CertReqMessages.getInstance(msg.getBody().getContent());

			CertReqMsg reqMsg = reqMsgs.toCertReqMsgArray()[0];

			assertEquals(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, reqMsg.getPopo().getType());
		}

		public virtual void testServerSideKey()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509CertificateHolder cert = makeV3Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaEncryptedValueBuilder encBldr = new JcaEncryptedValueBuilder((new JceAsymmetricKeyWrapper(kp.getPublic())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
			GeneralName recipient = new GeneralName(new X500Name("CN=Recip"));

			CertRepMessage msg = new CertRepMessage(null, new CertResponse[] {new CertResponse(new ASN1Integer(2), new PKIStatusInfo(PKIStatus.granted), new CertifiedKeyPair(new CertOrEncCert(CMPCertificate.getInstance(cert.getEncoded())), encBldr.build(kp.getPrivate()), null), null)});

			ContentSigner signer = (new JcaContentSignerBuilder("MD5WithRSAEncryption")).setProvider(BC).build(kp.getPrivate());
			ProtectedPKIMessage message = (new ProtectedPKIMessageBuilder(sender, recipient)).setBody(new PKIBody(PKIBody.TYPE_INIT_REP, msg)).addCMPCertificate(cert).build(signer);

			X509Certificate jcaCert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate(message.getCertificates()[0]);
			ContentVerifierProvider verifierProvider = (new JcaContentVerifierProviderBuilder()).setProvider(BC).build(jcaCert.getPublicKey());

			assertTrue(message.verify(verifierProvider));

			assertEquals(sender, message.getHeader().getSender());
			assertEquals(recipient, message.getHeader().getRecipient());

			CertRepMessage content = CertRepMessage.getInstance(message.getBody().getContent());

			CertResponse[] responseList = content.getResponse();

			assertEquals(1, responseList.Length);

			CertResponse response = responseList[0];

			assertEquals(PKIStatus.granted.getValue(), response.getStatus().getStatus());

			CertifiedKeyPair certKp = response.getCertifiedKeyPair();

			// steps to unwrap private key
			EncryptedValue encValue = certKp.getPrivateKey();

			// recover symmetric key
			AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), kp.getPrivate());

			byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();

			// recover private key
			PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(new EncryptedPrivateKeyInfo(encValue.getSymmAlg(), encValue.getEncValue().getBytes()));

			PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo((new JceInputDecryptorProviderBuilder()).setProvider("BC").build(secKeyBytes));

			assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
			assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), keyInfo.getEncoded()));
		}


		public virtual void testNotBeforeNotAfter()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();

			doNotBeforeNotAfterTest(kp, new DateTime(0L), new DateTime(60000L));
			doNotBeforeNotAfterTest(kp, null, new DateTime(60000L));
			doNotBeforeNotAfterTest(kp, new DateTime(0L), null);
		}

		private void doNotBeforeNotAfterTest(KeyPair kp, DateTime notBefore, DateTime notAfter)
		{
			CertificateRequestMessageBuilder builder = (new JcaCertificateRequestMessageBuilder(BigInteger.valueOf(1))).setPublicKey(kp.getPublic()).setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

			builder.setValidity(notBefore, notAfter);

			CertificateRequestMessage message = builder.build();

			if (notBefore != null)
			{
				assertEquals(notBefore.Ticks, message.getCertTemplate().getValidity().getNotBefore().getDate().Ticks);
			}
			else
			{
				assertNull(message.getCertTemplate().getValidity().getNotBefore());
			}

			if (notAfter != null)
			{
				assertEquals(notAfter.Ticks, message.getCertTemplate().getValidity().getNotAfter().getDate().Ticks);
			}
			else
			{
				assertNull(message.getCertTemplate().getValidity().getNotAfter());
			}
		}

		private static X509CertificateHolder makeV3Certificate(KeyPair subKP, string _subDN, KeyPair issKP, string _issDN)
		{

			PublicKey subPub = subKP.getPublic();
			PrivateKey issPriv = issKP.getPrivate();
			PublicKey issPub = issKP.getPublic();

			X509v3CertificateBuilder v1CertGen = new JcaX509v3CertificateBuilder(new X500Name(_issDN), BigInteger.valueOf(System.currentTimeMillis()), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(_subDN), subPub);

			ContentSigner signer = (new JcaContentSignerBuilder("SHA1WithRSA")).setProvider(BC).build(issPriv);

			X509CertificateHolder certHolder = v1CertGen.build(signer);

			ContentVerifierProvider verifier = (new JcaContentVerifierProviderBuilder()).setProvider(BC).build(issPub);

			assertTrue(certHolder.isSignatureValid(verifier));

			return certHolder;
		}

		private static PKIMessage loadMessage(string name)
		{
			string dataHome = System.getProperty(TEST_DATA_HOME);

			if (string.ReferenceEquals(dataHome, null))
			{
				throw new IllegalStateException(TEST_DATA_HOME + " property not set");
			}

			try
			{
				return PKIMessage.getInstance(ASN1Primitive.fromByteArray(Streams.readAll(new FileInputStream(dataHome + "/cmp/" + name))));
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.ToString());
			}
		}
	}
}