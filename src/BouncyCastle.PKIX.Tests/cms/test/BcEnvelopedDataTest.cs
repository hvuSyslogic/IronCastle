﻿using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.misc;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.cms;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using BcCMSContentEncryptorBuilder = org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
	using BcKEKEnvelopedRecipient = org.bouncycastle.cms.bc.BcKEKEnvelopedRecipient;
	using BcKEKRecipientInfoGenerator = org.bouncycastle.cms.bc.BcKEKRecipientInfoGenerator;
	using BcPasswordEnvelopedRecipient = org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
	using BcPasswordRecipientInfoGenerator = org.bouncycastle.cms.bc.BcPasswordRecipientInfoGenerator;
	using BcRSAKeyTransEnvelopedRecipient = org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
	using BcRSAKeyTransRecipientInfoGenerator = org.bouncycastle.cms.bc.BcRSAKeyTransRecipientInfoGenerator;
	using JceKeyAgreeEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
	using JceKeyAgreeRecipientId = org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
	using JceKeyAgreeRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using PrivateKeyFactory = org.bouncycastle.crypto.util.PrivateKeyFactory;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using BcAESSymmetricKeyUnwrapper = org.bouncycastle.@operator.bc.BcAESSymmetricKeyUnwrapper;
	using BcAESSymmetricKeyWrapper = org.bouncycastle.@operator.bc.BcAESSymmetricKeyWrapper;
	using BcSymmetricKeyUnwrapper = org.bouncycastle.@operator.bc.BcSymmetricKeyUnwrapper;
	using BcSymmetricKeyWrapper = org.bouncycastle.@operator.bc.BcSymmetricKeyWrapper;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class BcEnvelopedDataTest : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private static string _signDN;
		private static KeyPair _signKP;
		private static X509Certificate _signCert;

		private static string _origDN;
		private static KeyPair _origKP;
		private static X509Certificate _origCert;

		private static string _reciDN;
		private static string _reciDN2;
		private static KeyPair _reciKP;
		private static X509Certificate _reciCert;

		private static KeyPair _origEcKP;
		private static KeyPair _reciEcKP;
		private static X509Certificate _reciEcCert;
		private static KeyPair _reciEcKP2;
		private static X509Certificate _reciEcCert2;

		private static bool _initialised = false;

		private byte[] oldKEK = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQIxQaI/MD0CAQQwBwQFAQIDBAUwDQYJYIZIAWUDBAEFBQAEI" + "Fi2eHTPM4bQSjP4DUeDzJZLpfemW2gF1SPq7ZPHJi1mMIAGCSqGSIb3DQEHATAUBggqhkiG9w" + "0DBwQImtdGyUdGGt6ggAQYk9X9z01YFBkU7IlS3wmsKpm/zpZClTceAAAAAAAAAAAAAA==");

		private byte[] ecKeyAgreeMsgAES256 = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQIxgcShgcECAQOgQ6FBMAsGByqGSM49AgEF" + "AAMyAAPdXlSTpub+qqno9hUGkUDl+S3/ABhPziIB5yGU4678tgOgU5CiKG9Z" + "kfnabIJ3nZYwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBLQUAMFswWTAtMCgx" + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBCi/" + "rJRLbFwEVW6PcLLmojjW9lI/xGD7CfZzXrqXFw8iHaf3hTRau1gYMIAGCSqG" + "SIb3DQEHATAdBglghkgBZQMEASoEEMtCnKKPwccmyrbgeSIlA3qggAQQDLw8" + "pNJR97bPpj6baG99bQQQwhEDsoj5Xg1oOxojHVcYzAAAAAAAAAAAAAA=");

		private byte[] ecKeyAgreeMsgAES128 = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQIxgbShgbECAQOgQ6FBMAsGByqGSM49AgEF" + "AAMyAAL01JLEgKvKh5rbxI/hOxs/9WEezMIsAbUaZM4l5tn3CzXAN505nr5d" + "LhrcurMK+tAwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBBQUAMEswSTAtMCgx" + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBBhi" + "FLjc5g6aqDT3f8LomljOwl1WTrplUT8wgAYJKoZIhvcNAQcBMB0GCWCGSAFl" + "AwQBAgQQzXjms16Y69S/rB0EbHqRMaCABBAFmc/QdVW6LTKdEy97kaZzBBBa" + "fQuviUS03NycpojELx0bAAAAAAAAAAAAAA==");

		private byte[] ecKeyAgreeMsgDESEDE = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQIxgcahgcMCAQOgQ6FBMAsGByqGSM49AgEF" + "AAMyAALIici6Nx1WN5f0ThH2A8ht9ovm0thpC5JK54t73E1RDzCifePaoQo0" + "xd6sUqoyGaYwHAYJK4EFEIZIPwACMA8GCyqGSIb3DQEJEAMGBQAwWzBZMC0w" + "KDETMBEGA1UEAxMKQWRtaW4tTURTRTERMA8GA1UEChMINEJDVC0ySUQCAQEE" + "KJuqZQ1NB1vXrKPOnb4TCpYOsdm6GscWdwAAZlm2EHMp444j0s55J9wwgAYJ" + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAjwnsDMsafCrKCABBjyPvqFOVMKxxut" + "VfTx4fQlNGJN8S2ATRgECMcTQ/dsmeViAAAAAAAAAAAAAA==");

	   private byte[] ecMQVKeyAgreeMsgAES128 = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQIxgf2hgfoCAQOgQ6FBMAsGByqGSM49AgEF" + "AAMyAAPDKU+0H58tsjpoYmYCInMr/FayvCCkupebgsnpaGEB7qS9vzcNVUj6" + "mrnmiC2grpmhRwRFMEMwQTALBgcqhkjOPQIBBQADMgACZpD13z9c7DzRWx6S" + "0xdbq3S+EJ7vWO+YcHVjTD8NcQDcZcWASW899l1PkL936zsuMBoGCSuBBRCG" + "SD8AEDANBglghkgBZQMEAQUFADBLMEkwLTAoMRMwEQYDVQQDEwpBZG1pbi1N" + "RFNFMREwDwYDVQQKEwg0QkNULTJJRAIBAQQYFq58L71nyMK/70w3nc6zkkRy" + "RL7DHmpZMIAGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEDzRUpreBsZXWHBe" + "onxOtSmggAQQ7csAZXwT1lHUqoazoy8bhAQQq+9Zjj8iGdOWgyebbfj67QAA" + "AAAAAAAAAAA=");


		private byte[] ecKeyAgreeKey = Base64.decode("MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8vp7xVTbKSgYVU5Wc" + "hGkWbzaj+yUFETIWP1Dt7+WSpq3ikSPdl7PpHPqnPVZfoIWhZANiAgSYHTgxf+Dd" + "Tt84dUvuSKkFy3RhjxJmjwIscK6zbEUzKhcPQG2GHzXhWK5x1kov0I74XpGhVkya" + "ElH5K6SaOXiXAzcyNGggTOk4+ZFnz5Xl0pBje3zKxPhYu0SnCw7Pcqw=");

		private byte[] bobPrivRsaEncrypt = Base64.decode("MIIChQIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKnhZ5g/OdVf" + "8qCTQV6meYmFyDVdmpFb+x0B2hlwJhcPvaUi0DWFbXqYZhRBXM+3twg7CcmR" + "uBlpN235ZR572akzJKN/O7uvRgGGNjQyywcDWVL8hYsxBLjMGAgUSOZPHPtd" + "YMTgXB9T039T2GkB8QX4enDRvoPGXzjPHCyqaqfrAgMBAAECgYBnzUhMmg2P" + "mMIbZf8ig5xt8KYGHbztpwOIlPIcaw+LNd4Ogngwy+e6alatd8brUXlweQqg" + "9P5F4Kmy9Bnah5jWMIR05PxZbMHGd9ypkdB8MKCixQheIXFD/A0HPfD6bRSe" + "TmPwF1h5HEuYHD09sBvf+iU7o8AsmAX2EAnYh9sDGQJBANDDIsbeopkYdo+N" + "vKZ11mY/1I1FUox29XLE6/BGmvE+XKpVC5va3Wtt+Pw7PAhDk7Vb/s7q/WiE" + "I2Kv8zHCueUCQQDQUfweIrdb7bWOAcjXq/JY1PeClPNTqBlFy2bKKBlf4hAr" + "84/sajB0+E0R9KfEILVHIdxJAfkKICnwJAiEYH2PAkA0umTJSChXdNdVUN5q" + "SO8bKlocSHseIVnDYDubl6nA7xhmqU5iUjiEzuUJiEiUacUgFJlaV/4jbOSn" + "I3vQgLeFAkEAni+zN5r7CwZdV+EJBqRd2ZCWBgVfJAZAcpw6iIWchw+dYhKI" + "FmioNRobQ+g4wJhprwMKSDIETukPj3d9NDAlBwJAVxhn1grStavCunrnVNqc" + "BU+B1O8BiR4yPWnLMcRSyFRVJQA7HCp8JlDV6abXd8vPFfXuC9WN7rOvTKF8" + "Y0ZB9qANMAsGA1UdDzEEAwIAEA==");

		private byte[] rfc4134ex5_1 = Base64.decode("MIIBHgYJKoZIhvcNAQcDoIIBDzCCAQsCAQAxgcAwgb0CAQAwJjASMRAwDgYD" + "VQQDEwdDYXJsUlNBAhBGNGvHgABWvBHTbi7NXXHQMA0GCSqGSIb3DQEBAQUA" + "BIGAC3EN5nGIiJi2lsGPcP2iJ97a4e8kbKQz36zg6Z2i0yx6zYC4mZ7mX7FB" + "s3IWg+f6KgCLx3M1eCbWx8+MDFbbpXadCDgO8/nUkUNYeNxJtuzubGgzoyEd" + "8Ch4H/dd9gdzTd+taTEgS0ipdSJuNnkVY4/M652jKKHRLFf02hosdR8wQwYJ" + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAgtaMXpRwZRNYAgDsiSf8Z9P43LrY4O" + "xUk660cu1lXeCSFOSOpOJ7FuVyU=");

		private byte[] rfc4134ex5_2 = Base64.decode("MIIBZQYJKoZIhvcNAQcDoIIBVjCCAVICAQIxggEAMIG9AgEAMCYwEjEQMA4G" + "A1UEAxMHQ2FybFJTQQIQRjRrx4AAVrwR024uzV1x0DANBgkqhkiG9w0BAQEF" + "AASBgJQmQojGi7Z4IP+CVypBmNFoCDoEp87khtgyff2N4SmqD3RxPx+8hbLQ" + "t9i3YcMwcap+aiOkyqjMalT03VUC0XBOGv+HYI3HBZm/aFzxoq+YOXAWs5xl" + "GerZwTOc9j6AYlK4qXvnztR5SQ8TBjlzytm4V7zg+TGrnGVNQBNw47Ewoj4C" + "AQQwDQQLTWFpbExpc3RSQzIwEAYLKoZIhvcNAQkQAwcCAToEGHcUr5MSJ/g9" + "HnJVHsQ6X56VcwYb+OfojTBJBgkqhkiG9w0BBwEwGgYIKoZIhvcNAwIwDgIC" + "AKAECJwE0hkuKlWhgCBeKNXhojuej3org9Lt7n+wWxOhnky5V50vSpoYRfRR" + "yw==");

		public BcEnvelopedDataTest()
		{
		}

		private static void init()
		{
			if (!_initialised)
			{
				_initialised = true;

				if (Security.getProvider(BC) == null)
				{
					Security.addProvider(new BouncyCastleProvider());
				}

				_signDN = "O=Bouncy Castle, C=AU";
				_signKP = CMSTestUtil.makeKeyPair();
				_signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

				_origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
				_origKP = CMSTestUtil.makeKeyPair();
				_origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

				_reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
				_reciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
				_reciKP = CMSTestUtil.makeKeyPair();
				_reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

				_origEcKP = CMSTestUtil.makeEcDsaKeyPair();
				_reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
				_reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
				_reciEcKP2 = CMSTestUtil.makeEcDsaKeyPair();
				_reciEcCert2 = CMSTestUtil.makeCertificate(_reciEcKP2, _reciDN2, _signKP, _signDN);
			}
		}

		public static void Main(string[] args)
		{
			junit.textui.TestRunner.run(BcEnvelopedDataTest.suite());
		}

		public static Test suite()
		{
			init();

			return new CMSTestSetup(new TestSuite(typeof(BcEnvelopedDataTest)));
		}

		public virtual void testUnprotectedAttributes()
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			Hashtable attrs = new Hashtable();

			attrs.put(PKCSObjectIdentifiers_Fields.id_aa_contentHint, new Attribute(PKCSObjectIdentifiers_Fields.id_aa_contentHint, new DERSet(new DERUTF8String("Hint"))));
			attrs.put(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest, new Attribute(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

			AttributeTable attrTable = new AttributeTable(attrs);

			edGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.DES_EDE3_CBC.getId());

			attrTable = ed.getUnprotectedAttributes();

			assertEquals(attrs.size(), 2);

			assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers_Fields.id_aa_contentHint).getAttrValues().getObjectAt(0));
			assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest).getAttrValues().getObjectAt(0));

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(_reciKP.getPrivate().getEncoded())));

				assertEquals(true, Arrays.Equals(data, recData));
			}
		}

		public virtual void testKeyTrans()
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();


			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.DES_EDE3_CBC.getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
		}

		public virtual void testKeyTransRC4()
		{
			byte[] data = "WallaWallaBouncyCastle".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"))).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), (new ASN1ObjectIdentifier("1.2.840.113549.3.4")).getId());

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
		}

		public virtual void testKeyTrans128RC4()
		{
			byte[] data = "WallaWallaBouncyCastle".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testKeyTransLight128RC4()
		{
			byte[] data = "WallaWallaBouncyCastle".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.2.840.113549.3.4"), 128)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testKeyTransODES()
		{
			byte[] data = "WallaWallaBouncyCastle".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(new ASN1ObjectIdentifier("1.3.14.3.2.7"))).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testKeyTransSmallAES()
		{
			byte[] data = new byte[] {0, 1, 2, 3};

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));
				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testKeyTransCAST5()
		{
			tryKeyTrans(CMSAlgorithm.CAST5_CBC, MiscObjectIdentifiers_Fields.cast5CBC, 16, typeof(ASN1Sequence));
		}

		public virtual void testKeyTransRC2()
		{
			tryKeyTrans(CMSAlgorithm.RC2_CBC, PKCSObjectIdentifiers_Fields.RC2_CBC, 16, typeof(ASN1Sequence));
		}

		public virtual void testKeyTransAES128()
		{
			tryKeyTrans(CMSAlgorithm.AES128_CBC, NISTObjectIdentifiers_Fields.id_aes128_CBC, 16, typeof(DEROctetString));
		}

		public virtual void testKeyTransAES192()
		{
			tryKeyTrans(CMSAlgorithm.AES192_CBC, NISTObjectIdentifiers_Fields.id_aes192_CBC, 24, typeof(DEROctetString));
		}

		public virtual void testKeyTransAES256()
		{
			tryKeyTrans(CMSAlgorithm.AES256_CBC, NISTObjectIdentifiers_Fields.id_aes256_CBC, 32, typeof(DEROctetString));
		}

		private void tryKeyTrans(ASN1ObjectIdentifier generatorOID, ASN1ObjectIdentifier checkOID, int keySize, Class asn1Params)
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator(new BcRSAKeyTransRecipientInfoGenerator(new JcaX509CertificateHolder(_reciCert)));

			OutputEncryptor encryptor = (new BcCMSContentEncryptorBuilder(generatorOID)).build();
			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), encryptor);

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(checkOID.getId(), ed.getEncryptionAlgOID());
			assertEquals(keySize, ((byte[])encryptor.getKey().getRepresentation()).Length);

			if (asn1Params != null)
			{
				assertTrue(asn1Params.isAssignableFrom(ed.getContentEncryptionAlgorithm().getParameters().toASN1Primitive().GetType()));
			}

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			if (!it.hasNext())
			{
				fail("no recipients found");
			}

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(_reciKP.getPrivate().getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
		}

		public virtual void testAES128KEK()
		{
			SecretKey key = CMSTestUtil.makeAESKey(128);

			tryKekAlgorithm(new BcAESSymmetricKeyWrapper(new KeyParameter(key.getEncoded())), new BcAESSymmetricKeyUnwrapper(new KeyParameter(key.getEncoded())), NISTObjectIdentifiers_Fields.id_aes128_wrap);
		}

		public virtual void testAES192KEK()
		{
			SecretKey key = CMSTestUtil.makeAESKey(192);

			tryKekAlgorithm(new BcAESSymmetricKeyWrapper(new KeyParameter(key.getEncoded())), new BcAESSymmetricKeyUnwrapper(new KeyParameter(key.getEncoded())), NISTObjectIdentifiers_Fields.id_aes192_wrap);
		}

		public virtual void testAES256KEK()
		{
			SecretKey key = CMSTestUtil.makeAESKey(256);

			tryKekAlgorithm(new BcAESSymmetricKeyWrapper(new KeyParameter(key.getEncoded())), new BcAESSymmetricKeyUnwrapper(new KeyParameter(key.getEncoded())), NISTObjectIdentifiers_Fields.id_aes256_wrap);
		}

		private void tryKekAlgorithm(BcSymmetricKeyWrapper kekWrapper, BcSymmetricKeyUnwrapper kekUnwrapper, ASN1ObjectIdentifier algOid)
		{
			byte[] data = "WallaWallaWashington".GetBytes();
			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			byte[] kekId = new byte[] {1, 2, 3, 4, 5};

			edGen.addRecipientInfoGenerator(new BcKEKRecipientInfoGenerator(kekId, kekWrapper));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.DES_EDE3_CBC.getId());

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(algOid.getId(), recipient.getKeyEncryptionAlgOID());

				byte[] recData = recipient.getContent(new BcKEKEnvelopedRecipient(kekUnwrapper));

				assertTrue(Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testECKeyAgree()
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP)).addRecipient(_reciEcCert).setProvider(BC));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
			confirmNumberRecipients(recipients, 1);
		}

		public virtual void testECMQVKeyAgree()
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECMQV_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP)).addRecipient(_reciEcCert).setProvider(BC));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
			confirmNumberRecipients(recipients, 1);
		}

		public virtual void testECMQVKeyAgreeMultiple()
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			JceKeyAgreeRecipientInfoGenerator recipientGenerator = (new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECMQV_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP)).setProvider(BC);

			recipientGenerator.addRecipient(_reciEcCert);
			recipientGenerator.addRecipient(_reciEcCert2);

			edGen.addRecipientInfoGenerator(recipientGenerator);

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
			confirmDataReceived(recipients, data, _reciEcCert2, _reciEcKP2.getPrivate(), BC);
			confirmNumberRecipients(recipients, 2);
		}

		private static void confirmDataReceived(RecipientInformationStore recipients, byte[] expectedData, X509Certificate reciCert, PrivateKey reciPrivKey, string provider)
		{
			RecipientId rid = new JceKeyAgreeRecipientId(reciCert);

			RecipientInformation recipient = recipients.get(rid);
			assertNotNull(recipient);

			byte[] actualData = recipient.getContent((new JceKeyAgreeEnvelopedRecipient(reciPrivKey)).setProvider(provider));
			assertEquals(true, Arrays.Equals(expectedData, actualData));
		}

		private static void confirmNumberRecipients(RecipientInformationStore recipients, int count)
		{
			assertEquals(count, recipients.getRecipients().size());
		}

		public virtual void testECKeyAgreeVectors()
		{
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
			KeyFactory fact = KeyFactory.getInstance("ECDH", BC);
			PrivateKey privKey = fact.generatePrivate(privSpec);

			verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.42", ecKeyAgreeMsgAES256);
			verifyECKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecKeyAgreeMsgAES128);
			verifyECKeyAgreeVectors(privKey, "1.2.840.113549.3.7", ecKeyAgreeMsgDESEDE);
		}

		public virtual void testECMQVKeyAgreeVectors()
		{
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
			KeyFactory fact = KeyFactory.getInstance("ECDH", BC);
			PrivateKey privKey = fact.generatePrivate(privSpec);

			verifyECMQVKeyAgreeVectors(privKey, "2.16.840.1.101.3.4.1.2", ecMQVKeyAgreeMsgAES128);
		}

		public virtual void testPasswordAES256()
		{
			passwordTest(CMSAlgorithm.AES256_CBC);
			passwordUTF8Test(CMSAlgorithm.AES256_CBC);
		}

		public virtual void testPasswordDESEDE()
		{
			passwordTest(CMSAlgorithm.DES_EDE3_CBC);
			passwordUTF8Test(CMSAlgorithm.DES_EDE3_CBC);
		}

		public virtual void testRFC4134ex5_1()
		{
			byte[] data = Hex.decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

			KeyFactory kFact = KeyFactory.getInstance("RSA", BC);
			Key key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

			CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_1);

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals("1.2.840.113549.3.7", ed.getEncryptionAlgOID());

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(key.getEncoded()))));

				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testRFC4134ex5_2()
		{
			byte[] data = Hex.decode("5468697320697320736f6d652073616d706c6520636f6e74656e742e");

			KeyFactory kFact = KeyFactory.getInstance("RSA", BC);
			PrivateKey key = kFact.generatePrivate(new PKCS8EncodedKeySpec(bobPrivRsaEncrypt));

			CMSEnvelopedData ed = new CMSEnvelopedData(rfc4134ex5_2);

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals("1.2.840.113549.3.2", ed.getEncryptionAlgOID());

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				while (it.hasNext())
				{
					RecipientInformation recipient = (RecipientInformation)it.next();
					byte[] recData;

					if (recipient is KeyTransRecipientInformation)
					{
						recData = recipient.getContent(new BcRSAKeyTransEnvelopedRecipient(PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(key.getEncoded()))));

						assertEquals(true, Arrays.Equals(data, recData));
					}
				}
			}
			else
			{
				fail("no recipient found");
			}
		}

		public virtual void testOriginatorInfo()
		{
			CMSEnvelopedData env = new CMSEnvelopedData(CMSSampleMessages.originatorMessage);

			RecipientInformationStore recipients = env.getRecipientInfos();

			assertEquals(CMSAlgorithm.DES_EDE3_CBC.getId(), env.getEncryptionAlgOID());
		}

		private void passwordTest(ASN1ObjectIdentifier algorithm)
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator((new BcPasswordRecipientInfoGenerator(algorithm, "password".ToCharArray())).setPasswordConversionScheme(PasswordRecipient_Fields.PKCS5_SCHEME2).setSaltAndIterationCount(new byte[20], 5));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

				byte[] recData = recipient.getContent((new BcPasswordEnvelopedRecipient("password".ToCharArray())).setPasswordConversionScheme(PasswordRecipient_Fields.PKCS5_SCHEME2));

				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}

			//
			// try algorithm parameters constructor
			//
			it = c.iterator();

			RecipientInformation recipient = (RecipientInformation)it.next();

			byte[] recData = recipient.getContent((new BcPasswordEnvelopedRecipient("password".ToCharArray())).setPasswordConversionScheme(PasswordRecipient_Fields.PKCS5_SCHEME2));
			assertEquals(true, Arrays.Equals(data, recData));
		}

		private void passwordUTF8Test(ASN1ObjectIdentifier algorithm)
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

			edGen.addRecipientInfoGenerator((new BcPasswordRecipientInfoGenerator(algorithm, "abc\u5639\u563b".ToCharArray())).setSaltAndIterationCount(new byte[20], 5));

			CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(data), (new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).build());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				byte[] recData = recipient.getContent(new BcPasswordEnvelopedRecipient("abc\u5639\u563b".ToCharArray()));
				assertEquals(true, Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}

			//
			// try algorithm parameters constructor
			//
			it = c.iterator();

			RecipientInformation recipient = (RecipientInformation)it.next();

			byte[] recData = recipient.getContent(new BcPasswordEnvelopedRecipient("abc\u5639\u563b".ToCharArray()));
			assertEquals(true, Arrays.Equals(data, recData));
		}

		private void verifyECKeyAgreeVectors(PrivateKey privKey, string wrapAlg, byte[] message)
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedData ed = new CMSEnvelopedData(message);

			RecipientInformationStore recipients = ed.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(wrapAlg, ed.getEncryptionAlgOID());

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals("1.3.133.16.840.63.0.2", recipient.getKeyEncryptionAlgOID());

				byte[] recData = recipient.getContent((new JceKeyAgreeEnvelopedRecipient(privKey)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}

		private void verifyECMQVKeyAgreeVectors(PrivateKey privKey, string wrapAlg, byte[] message)
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedData ed = new CMSEnvelopedData(message);

			RecipientInformationStore recipients = ed.getRecipientInfos();

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			assertEquals(wrapAlg, ed.getEncryptionAlgOID());

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals("1.3.133.16.840.63.0.16", recipient.getKeyEncryptionAlgOID());

				byte[] recData = recipient.getContent((new JceKeyAgreeEnvelopedRecipient(privKey)).setProvider(BC));

				assertTrue(Arrays.Equals(data, recData));
			}
			else
			{
				fail("no recipient found");
			}
		}
	}

}