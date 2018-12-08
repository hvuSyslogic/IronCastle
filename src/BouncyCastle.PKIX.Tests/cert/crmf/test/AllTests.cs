using org.bouncycastle.asn1;
using org.bouncycastle.asn1.crmf;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.ntt;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.cert.crmf.test
{


	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CRMFObjectIdentifiers = org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
	using EncKeyWithID = org.bouncycastle.asn1.crmf.EncKeyWithID;
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using POPOSigningKey = org.bouncycastle.asn1.crmf.POPOSigningKey;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using BcFixedLengthMGF1Padder = org.bouncycastle.cert.crmf.bc.BcFixedLengthMGF1Padder;
	using JcaCertificateRequestMessage = org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
	using JcaCertificateRequestMessageBuilder = org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
	using JcaEncryptedValueBuilder = org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
	using JcaPKIArchiveControlBuilder = org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
	using JceAsymmetricValueDecryptorGenerator = org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
	using JceCRMFEncryptorBuilder = org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
	using JcePKMACValuesCalculator = org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaX509v1CertificateBuilder = org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSEnvelopedDataGenerator = org.bouncycastle.cms.CMSEnvelopedDataGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using RecipientId = org.bouncycastle.cms.RecipientId;
	using RecipientInformation = org.bouncycastle.cms.RecipientInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientId = org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;
	using JceAsymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyWrapper;
	using Arrays = org.bouncycastle.util.Arrays;

	public class AllTests : TestCase
	{
		private static readonly byte[] TEST_DATA = "Hello world!".getBytes();
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;
		private const string PASSPHRASE = "hello world";

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

		public virtual void testBasicMessage()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();

			JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

			certReqBuild.setSubject(new X500Principal("CN=Test")).setPublicKey(kp.getPublic()).setProofOfPossessionSigningKeySigner((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(kp.getPrivate()));

			JcaCertificateRequestMessage certReqMsg = (new JcaCertificateRequestMessage(certReqBuild.build())).setProvider(BC);


			POPOSigningKey popoSign = POPOSigningKey.getInstance(certReqMsg.toASN1Structure().getPopo().getObject());

			Signature sig = Signature.getInstance("SHA1withRSA", "BC");

			sig.initVerify(certReqMsg.getPublicKey());

			// this is the original approach in RFC 2511 - there's a typo in RFC 4211, the standard contradicts itself
			// between 4.1. 3 and then a couple of paragraphs later.
			sig.update(certReqMsg.toASN1Structure().getCertReq().getEncoded(ASN1Encoding_Fields.DER));

			TestCase.assertTrue(sig.verify(popoSign.getSignature().getOctets()));

			TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
			TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
		}

		public virtual void testBasicMessageWithArchiveControl()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

			certReqBuild.setSubject(new X500Principal("CN=Test")).setPublicKey(kp.getPublic());

			certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=Test"))
				.addRecipientGenerator((new JceKeyTransRecipientInfoGenerator(cert)).setProvider(BC)).build((new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC))).setProvider(BC).build()));

			JcaCertificateRequestMessage certReqMsg = (new JcaCertificateRequestMessage(certReqBuild.build())).setProvider(BC);

			TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
			TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

			checkCertReqMsgWithArchiveControl(kp, cert, certReqMsg);
			checkCertReqMsgWithArchiveControl(kp, cert, new JcaCertificateRequestMessage(certReqMsg.getEncoded()));
		}

		private void checkCertReqMsgWithArchiveControl(KeyPair kp, X509Certificate cert, JcaCertificateRequestMessage certReqMsg)
		{
			PKIArchiveControl archiveControl = (PKIArchiveControl)certReqMsg.getControl(CRMFObjectIdentifiers_Fields.id_regCtrl_pkiArchiveOptions);

			TestCase.assertEquals(PKIArchiveControl.encryptedPrivKey, archiveControl.getArchiveType());

			TestCase.assertTrue(archiveControl.isEnvelopedData());

			RecipientInformationStore recips = archiveControl.getEnvelopedData().getRecipientInfos();

			RecipientId recipientId = new JceKeyTransRecipientId(cert);

			RecipientInformation recipientInformation = recips.get(recipientId);

			TestCase.assertNotNull(recipientInformation);

			EncKeyWithID encKeyWithID = EncKeyWithID.getInstance(recipientInformation.getContent((new JceKeyTransEnvelopedRecipient(kp.getPrivate())).setProvider(BC)));

			TestCase.assertTrue(encKeyWithID.hasIdentifier());
			TestCase.assertFalse(encKeyWithID.isIdentifierUTF8String());

			TestCase.assertEquals(new GeneralName(X500Name.getInstance((new X500Principal("CN=Test")).getEncoded())), encKeyWithID.getIdentifier());
			TestCase.assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), encKeyWithID.getPrivateKey().getEncoded()));
		}

		public virtual void testProofOfPossessionWithoutSender()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

			certReqBuild.setPublicKey(kp.getPublic()).setAuthInfoPKMAC(new PKMACBuilder(new JcePKMACValuesCalculator()), "fred".ToCharArray()).setProofOfPossessionSigningKeySigner((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(kp.getPrivate()));

			certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
				.addRecipientGenerator((new JceKeyTransRecipientInfoGenerator(cert)).setProvider(BC)).build((new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC))).setProvider(BC).build()));

			JcaCertificateRequestMessage certReqMsg = (new JcaCertificateRequestMessage(certReqBuild.build().getEncoded())).setProvider(BC);

			// check that internal check on popo signing is working okay
			try
			{
				certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic()));
				TestCase.fail("IllegalStateException not thrown");
			}
			catch (IllegalStateException)
			{
				// ignore
			}

			TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic()), new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC)), "fred".ToCharArray()));

			TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

			certReqMsg = (new JcaCertificateRequestMessage(certReqBuild.build())).setProvider(BC);

					// check that internal check on popo signing is working okay
			try
			{
				certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic()));
				TestCase.fail("IllegalStateException not thrown");
			}
			catch (IllegalStateException)
			{
				// ignore
			}

			TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic()), new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC)), "fred".ToCharArray()));

			TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
		}

		public virtual void testEncryptedValueWithKey()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();

			JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder((new JceAsymmetricKeyWrapper(kp.getPublic())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			EncryptedValue value = build.build(kp.getPrivate());

			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			EncryptedValueParser parser = new EncryptedValueParser(value);

			PrivateKeyInfo privInfo = parser.readPrivateKeyInfo(decGen);

			TestCase.assertEquals(privInfo.getPrivateKeyAlgorithm(), parser.getIntendedAlg());

			TestCase.assertTrue(Arrays.areEqual(privInfo.getEncoded(), kp.getPrivate().getEncoded()));
		}

		public virtual void testProofOfPossessionWithSender()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

			certReqBuild.setPublicKey(kp.getPublic()).setAuthInfoSender(new X500Principal("CN=Test")).setProofOfPossessionSigningKeySigner((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(kp.getPrivate()));

			certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
										  .addRecipientGenerator((new JceKeyTransRecipientInfoGenerator(cert)).setProvider(BC)).build((new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC))).setProvider(BC).build()));

			JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

			// check that internal check on popo signing is working okay
			try
			{
				certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic()), new PKMACBuilder((new JcePKMACValuesCalculator()).setProvider(BC)), "fred".ToCharArray());

				fail("IllegalStateException not thrown");
			}
			catch (IllegalStateException)
			{
				// ignore
			}


			assertTrue(certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic())));

			assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
		}

		public virtual void testProofOfPossessionWithTemplate()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

			certReqBuild.setPublicKey(kp.getPublic()).setSubject(new X500Principal("CN=Test")).setAuthInfoSender(new X500Principal("CN=Test")).setProofOfPossessionSigningKeySigner((new JcaContentSignerBuilder("SHA1withRSA")).setProvider(BC).build(kp.getPrivate()));

			certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
										  .addRecipientGenerator((new JceKeyTransRecipientInfoGenerator(cert)).setProvider(BC)).build((new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC))).setProvider(BC).build()));

			JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

			assertTrue(certReqMsg.isValidSigningKeyPOP((new JcaContentVerifierProviderBuilder()).setProvider(BC).build(kp.getPublic())));

			assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
		}

		public virtual void testKeySizes()
		{
			verifyKeySize(NISTObjectIdentifiers_Fields.id_aes128_CBC, 128);
			verifyKeySize(NISTObjectIdentifiers_Fields.id_aes192_CBC, 192);
			verifyKeySize(NISTObjectIdentifiers_Fields.id_aes256_CBC, 256);

			verifyKeySize(NTTObjectIdentifiers_Fields.id_camellia128_cbc, 128);
			verifyKeySize(NTTObjectIdentifiers_Fields.id_camellia192_cbc, 192);
			verifyKeySize(NTTObjectIdentifiers_Fields.id_camellia256_cbc, 256);

			verifyKeySize(PKCSObjectIdentifiers_Fields.des_EDE3_CBC, 192);
		}

		private void verifyKeySize(ASN1ObjectIdentifier oid, int keySize)
		{
			JceCRMFEncryptorBuilder encryptorBuilder = (new JceCRMFEncryptorBuilder(oid)).setProvider(BC);

			OutputEncryptor outputEncryptor = encryptorBuilder.build();

			assertEquals(keySize / 8, ((byte[])(outputEncryptor.getKey().getRepresentation())).Length);
		}

		public virtual void testEncryptedValue()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder((new JceAsymmetricKeyWrapper(cert.getPublicKey())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());
			EncryptedValue value = build.build(cert);
			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			// try direct
			encryptedValueParserTest(value, decGen, cert);

			// try indirect
			encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
		}

		public virtual void testEncryptedValueOAEP1()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(2048);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE);

			JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder((new JceAsymmetricKeyWrapper(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, new RSAESOAEPparams(sha256, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, sha256), RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)), cert.getPublicKey())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			EncryptedValue value = build.build(cert);
			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			// try direct
			encryptedValueParserTest(value, decGen, cert);

			// try indirect
			encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
		}

		public virtual void testEncryptedValueOAEP2()
		{
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(2048);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder((new JceAsymmetricKeyWrapper(new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), new PSource.PSpecified(new byte[2])), cert.getPublicKey())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			EncryptedValue value = build.build(cert);

			assertEquals(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, value.getKeyAlg().getAlgorithm());
			assertEquals(NISTObjectIdentifiers_Fields.id_sha256, RSAESOAEPparams.getInstance(value.getKeyAlg().getParameters()).getHashAlgorithm().getAlgorithm());
			assertEquals(new DEROctetString(new byte[2]), RSAESOAEPparams.getInstance(value.getKeyAlg().getParameters()).getPSourceAlgorithm().getParameters());

			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			// try direct
			encryptedValueParserTest(value, decGen, cert);

			// try indirect
			encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
		}

		private void encryptedValueParserTest(EncryptedValue value, ValueDecryptorGenerator decGen, X509Certificate cert)
		{
			EncryptedValueParser parser = new EncryptedValueParser(value);

			X509CertificateHolder holder = parser.readCertificateHolder(decGen);

			assertTrue(Arrays.areEqual(cert.getEncoded(), holder.getEncoded()));
		}

		public virtual void testEncryptedValuePassphrase()
		{
			char[] passphrase = PASSPHRASE.ToCharArray();
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			EncryptedValueBuilder build = new EncryptedValueBuilder((new JceAsymmetricKeyWrapper(cert.getPublicKey())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());
			EncryptedValue value = build.build(passphrase);
			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			// try direct
			encryptedValuePassphraseParserTest(value, null, decGen, cert);

			// try indirect
			encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), null, decGen, cert);
		}

		public virtual void testEncryptedValuePassphraseWithPadding()
		{
			char[] passphrase = PASSPHRASE.ToCharArray();
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

			kGen.initialize(512);

			KeyPair kp = kGen.generateKeyPair();
			X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

			BcFixedLengthMGF1Padder mgf1Padder = new BcFixedLengthMGF1Padder(200, new SecureRandom());
			EncryptedValueBuilder build = new EncryptedValueBuilder((new JceAsymmetricKeyWrapper(cert.getPublicKey())).setProvider(BC), (new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build(), mgf1Padder);
			EncryptedValue value = build.build(passphrase);
			ValueDecryptorGenerator decGen = (new JceAsymmetricValueDecryptorGenerator(kp.getPrivate())).setProvider(BC);

			// try direct
			encryptedValuePassphraseParserTest(value, mgf1Padder, decGen, cert);

			// try indirect
			encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), mgf1Padder, decGen, cert);
		}

		private void encryptedValuePassphraseParserTest(EncryptedValue value, EncryptedValuePadder padder, ValueDecryptorGenerator decGen, X509Certificate cert)
		{
			EncryptedValueParser parser = new EncryptedValueParser(value, padder);

			assertTrue(Arrays.areEqual(PASSPHRASE.ToCharArray(), parser.readPassphrase(decGen)));
		}

		private static X509Certificate makeV1Certificate(KeyPair subKP, string _subDN, KeyPair issKP, string _issDN)
		{

			PublicKey subPub = subKP.getPublic();
			PrivateKey issPriv = issKP.getPrivate();
			PublicKey issPub = issKP.getPublic();

			X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(new X500Name(_issDN), BigInteger.valueOf(System.currentTimeMillis()), new DateTime(System.currentTimeMillis()), new DateTime(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(_subDN), subPub);

			JcaContentSignerBuilder signerBuilder = null;

			if (issPub is RSAPublicKey)
			{
				signerBuilder = new JcaContentSignerBuilder("SHA1WithRSA");
			}
			else if (issPub.getAlgorithm().Equals("DSA"))
			{
				signerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
			}
			else if (issPub.getAlgorithm().Equals("ECDSA"))
			{
				signerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
			}
			else if (issPub.getAlgorithm().Equals("ECGOST3410"))
			{
				signerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
			}
			else
			{
				signerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
			}

			signerBuilder.setProvider(BC);

			X509Certificate _cert = (new JcaX509CertificateConverter()).setProvider(BC).getCertificate(v1CertGen.build(signerBuilder.build(issPriv)));

			_cert.checkValidity(DateTime.Now);
			_cert.verify(issPub);

			return _cert;
		}
	}
}