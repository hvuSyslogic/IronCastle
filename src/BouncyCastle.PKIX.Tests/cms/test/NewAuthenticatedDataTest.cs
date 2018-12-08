using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms.test
{

	using Assert = junit.framework.Assert;
	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using AuthenticatedData = org.bouncycastle.asn1.cms.AuthenticatedData;
	using CCMParameters = org.bouncycastle.asn1.cms.CCMParameters;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using ASN1Dump = org.bouncycastle.asn1.util.ASN1Dump;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JceCMSMacCalculatorBuilder = org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
	using JceKEKAuthenticatedRecipient = org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
	using JceKEKRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
	using JceKeyAgreeAuthenticatedRecipient = org.bouncycastle.cms.jcajce.JceKeyAgreeAuthenticatedRecipient;
	using JceKeyAgreeRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
	using JceKeyTransAuthenticatedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using JcePasswordAuthenticatedRecipient = org.bouncycastle.cms.jcajce.JcePasswordAuthenticatedRecipient;
	using JcePasswordRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class NewAuthenticatedDataTest : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private static string _signDN;
		private static KeyPair _signKP;
		private static X509Certificate _signCert;

		private static string _origDN;
		private static KeyPair _origKP;
		private static X509Certificate _origCert;

		private static string _reciDN;
		private static KeyPair _reciKP;
		private static X509Certificate _reciCert;

		private static KeyPair _origEcKP;
		private static KeyPair _reciEcKP;
		private static X509Certificate _reciEcCert;

		private static bool _initialised = false;

		public bool DEBUG = true;

		private static void init()
		{
			if (!_initialised)
			{
				_initialised = true;
				Security.addProvider(new BouncyCastleProvider());

				_signDN = "O=Bouncy Castle, C=AU";
				_signKP = CMSTestUtil.makeKeyPair();
				_signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

				_origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
				_origKP = CMSTestUtil.makeKeyPair();
				_origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

				_reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
				_reciKP = CMSTestUtil.makeKeyPair();
				_reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

				_origEcKP = CMSTestUtil.makeEcDsaKeyPair();
				_reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
				_reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
			}
		}

		public virtual void setUp()
		{
			init();
		}

		public NewAuthenticatedDataTest(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(NewAuthenticatedDataTest));
		}

		public static Test suite()
		{
			init();

			return new CMSTestSetup(new TestSuite(typeof(NewAuthenticatedDataTest)));
		}

		public virtual void testKeyTransDESede()
		{
			tryKeyTrans(CMSAlgorithm.DES_EDE3_CBC);
		}

		public virtual void testKeyTransDESedeWithDigest()
		{
			tryKeyTransWithDigest(CMSAlgorithm.DES_EDE3_CBC);
		}

		public virtual void testKeyTransRC2()
		{
			tryKeyTrans(CMSAlgorithm.RC2_CBC);
		}

		public virtual void testKEKDESede()
		{
			tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"));

			DEROctetString iv = new DEROctetString(Hex.decode("0001020304050607"));
			tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"), iv.getEncoded());
		}

		public virtual void testKEKDESedeWithDigest()
		{
			tryKekAlgorithmWithDigest(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
		}

		public virtual void testPasswordAES256()
		{
			passwordTest(CMSAuthenticatedDataGenerator.AES256_CBC);
		}

		public virtual void testECKeyAgree()
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			JceKeyAgreeRecipientInfoGenerator recipientGenerator = (new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP)).setProvider(BC);

			recipientGenerator.addRecipient(_reciEcCert);

			adGen.addRecipientInfoGenerator(recipientGenerator);

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent((new JceKeyAgreeAuthenticatedRecipient(_reciEcKP.getPrivate())).setProvider(BC));
				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testEncoding()
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());

			ad = new CMSAuthenticatedData(ad.getEncoded());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(CMSAuthenticatedDataGenerator.DES_EDE3_CBC, ad.getMacAlgOID());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
		}

		public virtual void testOriginatorInfo()
		{
			byte[] data = "Eric H. Echidna".GetBytes();
			ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

			adGen.setOriginatorInfo((new OriginatorInfoGenerator(origCert)).generate());

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build());

			assertTrue(ad.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), macAlg.getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
		}

		public virtual void testAES256CCM()
		{
			byte[] data = "Eric H. Echidna".GetBytes();
			ASN1ObjectIdentifier macAlg = CMSAlgorithm.AES256_CCM;
			AlgorithmParameters algParams = AlgorithmParameters.getInstance("CCM", BC);

			algParams.init((new CCMParameters(Hex.decode("000102030405060708090a0b"), 16)).getEncoded());

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

			adGen.setOriginatorInfo((new OriginatorInfoGenerator(origCert)).generate());

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(macAlg)).setAlgorithmParameters(algParams).setProvider(BC).build());

			assertTrue(ad.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), macAlg.getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertEquals(16, ad.getMac().Length);
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
		}

		public virtual void testCMSAlgorithmProtection()
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
			DigestCalculatorProvider calcProvider = (new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build();

			byte[] kekId = new byte[]{1, 2, 3, 4, 5};
			SecretKey kek = CMSTestUtil.makeDesede192Key();

			adGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId, kek)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build(), calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1)));

			checkData(data, kek, ad);

			ContentInfo adInfo = ad.toASN1Structure();
			AuthenticatedData iAd = AuthenticatedData.getInstance(adInfo.getContent().toASN1Primitive().getEncoded());

			try
			{
				new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers_Fields.authenticatedData, new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), iAd.getMacAlgorithm(), new AlgorithmIdentifier(TeleTrusTObjectIdentifiers_Fields.ripemd160, DERNull.INSTANCE), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
			}
			catch (CMSException e)
			{
				Assert.assertEquals(e.Message, "CMS Algorithm Identifier Protection check failed for digestAlgorithm");
			}

			AlgorithmIdentifier newDigAlgId = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
			Assert.assertFalse(iAd.getDigestAlgorithm().Equals(newDigAlgId));
			checkData(data, kek, new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers_Fields.authenticatedData, new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), iAd.getMacAlgorithm(), newDigAlgId, iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider));

			try
			{
				new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers_Fields.authenticatedData, new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), new AlgorithmIdentifier(CMSAlgorithm.AES192_CBC), iAd.getDigestAlgorithm(), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
			}
			catch (CMSException e)
			{
				Assert.assertEquals(e.Message, "CMS Algorithm Identifier Protection check failed for macAlgorithm");
			}

			try
			{
				AlgorithmIdentifier newMacAlgId = new AlgorithmIdentifier(CMSAlgorithm.DES_EDE3_CBC);
				Assert.assertFalse(iAd.getMacAlgorithm().Equals(newMacAlgId));
				new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers_Fields.authenticatedData, new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), newMacAlgId, iAd.getDigestAlgorithm(), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
			}
			catch (CMSException e)
			{
				Assert.assertEquals(e.Message, "CMS Algorithm Identifier Protection check failed for macAlgorithm");
			}
		}

		private void checkData(byte[] data, SecretKey kek, CMSAuthenticatedData ad)
		{
			RecipientInformationStore recipients = ad.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent((new JceKEKAuthenticatedRecipient(kek)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
				assertTrue(Arrays.Equals(ad.getContentDigest(), recipient.getContentDigest()));
			}
			else
			{
				fail("no recipient found");
			}
		}

		private void tryKeyTrans(ASN1ObjectIdentifier macAlg)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), macAlg.getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
		}

		private void tryKeyTransWithDigest(ASN1ObjectIdentifier macAlg)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
			DigestCalculatorProvider calcProvider = (new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build();

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build(), calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1)));

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), macAlg.getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
				assertTrue(Arrays.Equals(ad.getContentDigest(), recipient.getContentDigest()));
			}
		}

		private void tryKekAlgorithm(SecretKey kek, ASN1ObjectIdentifier algOid)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			byte[] kekId = new byte[]{1, 2, 3, 4, 5};

			adGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId, kek)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

				byte[] recData = recipient.getContent((new JceKEKAuthenticatedRecipient(kek)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
			else
			{
				fail("no recipient found");
			}
		}

		private void tryKekAlgorithm(SecretKey kek, ASN1ObjectIdentifier algOid, byte[] encodedParameters)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			byte[] kekId = new byte[]{1, 2, 3, 4, 5};

			adGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId, kek)).setProvider(BC));

			AlgorithmParameters algParams = AlgorithmParameters.getInstance(CMSAlgorithm.DES_EDE3_CBC.getId(), "BC");

			algParams.init(encodedParameters);

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setAlgorithmParameters(algParams).setProvider(BC).build());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);
			assertEquals(ad.getMacAlgorithm().getParameters(), ASN1Primitive.fromByteArray(encodedParameters));

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

				byte[] recData = recipient.getContent((new JceKEKAuthenticatedRecipient(kek)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
			else
			{
				fail("no recipient found");
			}
		}

		private void tryKekAlgorithmWithDigest(SecretKey kek, ASN1ObjectIdentifier algOid)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
			DigestCalculatorProvider calcProvider = (new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build();

			byte[] kekId = new byte[]{1, 2, 3, 4, 5};

			adGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId, kek)).setProvider(BC));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build(), calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1)));

			RecipientInformationStore recipients = ad.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

				byte[] recData = recipient.getContent((new JceKEKAuthenticatedRecipient(kek)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
				assertTrue(Arrays.Equals(ad.getContentDigest(), recipient.getContentDigest()));
			}
			else
			{
				fail("no recipient found");
			}
		}

		private void passwordTest(string algorithm)
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

			adGen.addRecipientInfoGenerator((new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "password".ToCharArray())).setProvider(BC).setSaltAndIterationCount(new byte[20], 5));

			CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), (new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());

			RecipientInformationStore recipients = ad.getRecipientInfos();

			assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

				PasswordRecipient pbeRep = (new JcePasswordAuthenticatedRecipient("password".ToCharArray())).setProvider(BC);

				byte[] recData = recipient.getContent(pbeRep);

				assertTrue(Arrays.Equals(data, recData));
				assertTrue(Arrays.Equals(ad.getMac(), recipient.getMac()));
			}
			else
			{
				fail("no recipient found");
			}
		}
	}
}