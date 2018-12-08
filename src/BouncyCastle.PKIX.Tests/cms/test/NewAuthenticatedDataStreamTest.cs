using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JceCMSMacCalculatorBuilder = org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
	using JceKeyTransAuthenticatedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;

	public class NewAuthenticatedDataStreamTest : TestCase
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

		public NewAuthenticatedDataStreamTest(string name) : base(name)
		{
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(typeof(NewAuthenticatedDataStreamTest));
		}

		public static Test suite()
		{
			init();

			return new CMSTestSetup(new TestSuite(typeof(NewAuthenticatedDataStreamTest)));
		}

		public virtual void testKeyTransDESede()
		{
			tryKeyTrans(CMSAlgorithm.DES_EDE3_CBC);
		}

		public virtual void testKeyTransDESedeWithDigest()
		{
			tryKeyTransWithDigest(CMSAlgorithm.DES_EDE3_CBC);
		}

		public virtual void testOriginatorInfo()
		{
			ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

			adGen.setOriginatorInfo((new OriginatorInfoGenerator(origCert)).generate());

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			OutputStream aOut = adGen.open(bOut, (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build());

			aOut.write(data);

			aOut.close();

			CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray());

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

		private void tryKeyTrans(ASN1ObjectIdentifier macAlg)
		{
			byte[] data = "Eric H. Echidna".GetBytes();

			CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			OutputStream aOut = adGen.open(bOut, (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build());

			aOut.write(data);

			aOut.close();

			CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray());

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

			CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DigestCalculatorProvider calcProvider = (new JcaDigestCalculatorProviderBuilder()).setProvider(BC).build();

			adGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			OutputStream aOut = adGen.open(bOut, (new JceCMSMacCalculatorBuilder(macAlg)).setProvider(BC).build(), calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1)));

			aOut.write(data);

			aOut.close();

			CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray(), calcProvider);

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
	}
}