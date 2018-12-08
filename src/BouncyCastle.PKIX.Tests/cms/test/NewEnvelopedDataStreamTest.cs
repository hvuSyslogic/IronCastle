using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.cms.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JceCMSContentEncryptorBuilder = org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
	using JceKEKEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
	using JceKEKRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
	using JceKeyAgreeEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
	using JceKeyAgreeRecipientId = org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
	using JceKeyAgreeRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
	using JceKeyTransEnvelopedRecipient = org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
	using JceKeyTransRecipientInfoGenerator = org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class NewEnvelopedDataStreamTest : TestCase
	{
		private const string BC = BouncyCastleProvider.PROVIDER_NAME;

		private const int BUFFER_SIZE = 4000;
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

		public NewEnvelopedDataStreamTest()
		{
		}

		private static void init()
		{
			if (!_initialised)
			{
				_initialised = true;

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

		public virtual void testWorkingData()
		{
			byte[] keyData = Base64.decode("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKrAz/SQKrcQ" + "nj9IxHIfKDbuXsMqUpI06s2gps6fp7RDNvtUDDMOciWGFhD45YSy8GO0mPx3" + "Nkc7vKBqX4TLcqLUz7kXGOHGOwiPZoNF+9jBMPNROe/B0My0PkWg9tuq+nxN" + "64oD47+JvDwrpNOS5wsYavXeAW8Anv9ZzHLU7KwZAgMBAAECgYA/fqdVt+5K" + "WKGfwr1Z+oAHvSf7xtchiw/tGtosZ24DOCNP3fcTXUHQ9kVqVkNyzt9ZFCT3" + "bJUAdBQ2SpfuV4DusVeQZVzcROKeA09nPkxBpTefWbSDQGhb+eZq9L8JDRSW" + "HyYqs+MBoUpLw7GKtZiJkZyY6CsYkAnQ+uYVWq/TIQJBAP5zafO4HUV/w4KD" + "VJi+ua+GYF1Sg1t/dYL1kXO9GP1p75YAmtm6LdnOCas7wj70/G1YlPGkOP0V" + "GFzeG5KAmAUCQQCryvKU9nwWA+kypcQT9Yr1P4vGS0APYoBThnZq7jEPc5Cm" + "ZI82yseSxSeea0+8KQbZ5mvh1p3qImDLEH/iNSQFAkAghS+tboKPN10NeSt+" + "uiGRRWNbiggv0YJ7Uldcq3ZeLQPp7/naiekCRUsHD4Qr97OrZf7jQ1HlRqTu" + "eZScjMLhAkBNUMZCQnhwFAyEzdPkQ7LpU1MdyEopYmRssuxijZao5JLqQAGw" + "YCzXokGFa7hz72b09F4DQurJL/WuDlvvu4jdAkEAxwT9lylvfSfEQw4/qQgZ" + "MFB26gqB6Gqs1pHIZCzdliKx5BO3VDeUGfXMI8yOkbXoWbYx5xPid/+N8R//" + "+sxLBw==");

			byte[] envData = Base64.decode("MIAGCSqGSIb3DQEHA6CAMIACAQAxgcQwgcECAQAwKjAlMRYwFAYDVQQKEw1C" + "b3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVQIBHjANBgkqhkiG9w0BAQEFAASB" + "gDmnaDZ0vDJNlaUSYyEXsgbaUH+itNTjCOgv77QTX2ImXj+kTctM19PQF2I1" + "0/NL0fjakvCgBTHKmk13a7jqB6cX3bysenHNrglHsgNGgeXQ7ggAq5fV/JQQ" + "T7rSxEtuwpbuHQnoVUZahOHVKy/a0uLr9iIh1A3y+yZTZaG505ZJMIAGCSqG" + "SIb3DQEHATAdBglghkgBZQMEAQIEENmkYNbDXiZxJWtq82qIRZKggAQgkOGr" + "1JcTsADStez1eY4+rO4DtyBIyUYQ3pilnbirfPkAAAAAAAAAAAAA");


			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(envData);

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
			KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
			PrivateKey priKey = keyFact.generatePrivate(keySpec);
			byte[] data = Hex.decode("57616c6c6157616c6c6157617368696e67746f6e");

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(priKey)).setProvider(BC));

				assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}
		}

		private void verifyData(ByteArrayOutputStream encodedStream, string expectedOid, byte[] expectedData)
		{
			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(encodedStream.toByteArray());
			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), expectedOid);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertEquals(true, Arrays.Equals(expectedData, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}
		}

		public virtual void testUnprotectedAttributes()
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			Hashtable attrs = new Hashtable();

			attrs.put(PKCSObjectIdentifiers_Fields.id_aa_contentHint, new Attribute(PKCSObjectIdentifiers_Fields.id_aa_contentHint, new DERSet(new DERUTF8String("Hint"))));
			attrs.put(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest, new Attribute(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

			AttributeTable attrTable = new AttributeTable(attrs);

			edGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ed = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ed.getRecipientInfos();

			Collection c = recipients.getRecipients();

			assertEquals(1, c.size());

			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				byte[] recData = recipient.getContent((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertEquals(true, Arrays.Equals(data, recData));
			}

			attrTable = ed.getUnprotectedAttributes();

			assertEquals(attrs.size(), 2);

			assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers_Fields.id_aa_contentHint).getAttrValues().getObjectAt(0));
			assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers_Fields.id_aa_receiptRequest).getAttrValues().getObjectAt(0));

		}

		public virtual void testKeyTransAES128BufferedStream()
		{
			byte[] data = new byte[2000];

			for (int i = 0; i != 2000; i++)
			{
				data[i] = unchecked((byte)(i & 0xff));
			}

			//
			// unbuffered
			//
			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			for (int i = 0; i != 2000; i++)
			{
				@out.write(data[i]);
			}

			@out.close();

			verifyData(bOut, CMSEnvelopedDataGenerator.AES128_CBC, data);

			int unbufferedLength = bOut.toByteArray().length;

			//
			// Using buffered output - should be == to unbuffered
			//
			edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			bOut = new ByteArrayOutputStream();

			@out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			BufferedOutputStream bfOut = new BufferedOutputStream(@out, 300);

			for (int i = 0; i != 2000; i++)
			{
				bfOut.write(data[i]);
			}

			bfOut.close();

			verifyData(bOut, CMSEnvelopedDataGenerator.AES128_CBC, data);

			assertTrue(bOut.toByteArray().length == unbufferedLength);
		}

		public virtual void testKeyTransAES128Buffered()
		{
			byte[] data = new byte[2000];

			for (int i = 0; i != 2000; i++)
			{
				data[i] = unchecked((byte)(i & 0xff));
			}

			//
			// unbuffered
			//
			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			for (int i = 0; i != 2000; i++)
			{
				@out.write(data[i]);
			}

			@out.close();

			verifyData(bOut, CMSEnvelopedDataGenerator.AES128_CBC, data);

			int unbufferedLength = bOut.toByteArray().length;

			//
			// buffered - less than default of 1000
			//
			edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.setBufferSize(300);

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			bOut = new ByteArrayOutputStream();

			@out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			for (int i = 0; i != 2000; i++)
			{
				@out.write(data[i]);
			}

			@out.close();

			verifyData(bOut, CMSEnvelopedDataGenerator.AES128_CBC, data);

			assertTrue(bOut.toByteArray().length > unbufferedLength);
		}

		public virtual void testKeyTransAES128Der()
		{
			byte[] data = new byte[2000];

			for (int i = 0; i != 2000; i++)
			{
				data[i] = unchecked((byte)(i & 0xff));
			}

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			for (int i = 0; i != 2000; i++)
			{
				@out.write(data[i]);
			}

			@out.close();

			// convert to DER
			ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());

			bOut.reset();

			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(aIn.readObject());

			verifyData(bOut, CMSEnvelopedDataGenerator.AES128_CBC, data);
		}

		public virtual void testKeyTransAES128Throughput()
		{
			byte[] data = new byte[40001];

			for (int i = 0; i != data.Length; i++)
			{
				data[i] = unchecked((byte)(i & 0xff));
			}

			//
			// buffered
			//
			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.setBufferSize(BUFFER_SIZE);

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			for (int i = 0; i != data.Length; i++)
			{
				@out.write(data[i]);
			}

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());
			RecipientInformationStore recipients = ep.getRecipientInfos();
			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			if (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

				InputStream dataStream = recData.getContentStream();
				ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
				int len;
				byte[] buf = new byte[BUFFER_SIZE];
				int count = 0;

				while (count != 10 && (len = dataStream.read(buf)) > 0)
				{
					assertEquals(buf.Length, len);

					dataOut.write(buf);
					count++;
				}

				len = dataStream.read(buf);
				dataOut.write(buf, 0, len);

				assertEquals(true, Arrays.Equals(data, dataOut.toByteArray()));
			}
			else
			{
				fail("recipient not found.");
			}
		}

		public virtual void testKeyTransAES128AndOriginatorInfo()
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

			edGen.setOriginatorInfo((new OriginatorInfoGenerator(origCert)).generate());

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			assertTrue(ep.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}

			ep.close();
		}

		public virtual void testKeyTransAES128()
		{
			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());

			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider(BC));

				assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}

			ep.close();
		}

		public virtual void testKeyTransCAST5SunJCE()
		{
			if (Security.getProvider("SunJCE") == null)
			{
				return;
			}

			string version = System.getProperty("java.version");
			if (version.StartsWith("1.4", StringComparison.Ordinal) || version.StartsWith("1.3", StringComparison.Ordinal))
			{
				return;
			}

			byte[] data = "WallaWallaWashington".GetBytes();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			edGen.addRecipientInfoGenerator((new JceKeyTransRecipientInfoGenerator(_reciCert)).setProvider("SunJCE"));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.CAST5_CBC)).setProvider(BC).build());

			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.CAST5_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers_Fields.rsaEncryption.getId());

				CMSTypedStream recData = recipient.getContentStream((new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate())).setProvider("SunJCE").setContentProvider(BC));

				assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}

			ep.close();
		}

		public virtual void testAESKEK()
		{
			byte[] data = "WallaWallaWashington".GetBytes();
			SecretKey kek = CMSTestUtil.makeAES192Key();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			byte[] kekId = new byte[] {1, 2, 3, 4, 5};

			edGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId, kek)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());
			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

			Collection c = recipients.getRecipients();
			Iterator it = c.iterator();

			while (it.hasNext())
			{
				RecipientInformation recipient = (RecipientInformation)it.next();

				assertEquals(recipient.getKeyEncryptionAlgOID(), "2.16.840.1.101.3.4.1.25");

				CMSTypedStream recData = recipient.getContentStream((new JceKEKEnvelopedRecipient(kek)).setProvider(BC));

				assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
			}

			ep.close();
		}

		public virtual void testTwoAESKEK()
		{
			byte[] data = "WallaWallaWashington".GetBytes();
			SecretKey kek1 = CMSTestUtil.makeAES192Key();
			SecretKey kek2 = CMSTestUtil.makeAES192Key();

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			byte[] kekId1 = new byte[] {1, 2, 3, 4, 5};
			byte[] kekId2 = new byte[] {5, 4, 3, 2, 1};

			edGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId1, kek1)).setProvider(BC));
			edGen.addRecipientInfoGenerator((new JceKEKRecipientInfoGenerator(kekId2, kek2)).setProvider(BC));

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)).setProvider(BC).build());
			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

			RecipientId recSel = new KEKRecipientId(kekId2);

			RecipientInformation recipient = recipients.get(recSel);

			assertEquals(recipient.getKeyEncryptionAlgOID(), "2.16.840.1.101.3.4.1.25");

			CMSTypedStream recData = recipient.getContentStream((new JceKEKEnvelopedRecipient(kek2)).setProvider(BC));

			assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

			ep.close();
		}

		public virtual void testECKeyAgree()
		{
			byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

			CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

			JceKeyAgreeRecipientInfoGenerator recipientGenerator = (new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP)).setProvider(BC);

			recipientGenerator.addRecipient(_reciEcCert);

			edGen.addRecipientInfoGenerator(recipientGenerator);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream @out = edGen.open(bOut, (new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)).setProvider(BC).build());
			@out.write(data);

			@out.close();

			CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

			RecipientInformationStore recipients = ep.getRecipientInfos();

			assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

			RecipientId recSel = new JceKeyAgreeRecipientId(_reciEcCert);

			RecipientInformation recipient = recipients.get(recSel);

			CMSTypedStream recData = recipient.getContentStream((new JceKeyAgreeEnvelopedRecipient(_reciEcKP.getPrivate())).setProvider(BC));

			assertEquals(true, Arrays.Equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

			ep.close();
		}

		public virtual void testOriginatorInfo()
		{
			CMSEnvelopedDataParser env = new CMSEnvelopedDataParser(CMSSampleMessages.originatorMessage);

			OriginatorInformation origInfo = env.getOriginatorInfo();

			RecipientInformationStore recipients = env.getRecipientInfos();

			assertEquals(new X500Name("C=US,O=U.S. Government,OU=HSPD12Lab,OU=Agents,CN=user1"), ((X509CertificateHolder)origInfo.getCertificates().getMatches(null).iterator().next()).getSubject());
			assertEquals(CMSEnvelopedDataGenerator.DES_EDE3_CBC, env.getEncryptionAlgOID());
		}

		public static Test suite()
		{
			return new CMSTestSetup(new TestSuite(typeof(NewEnvelopedDataStreamTest)));
		}
	}

}