using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CertificationRequest = org.bouncycastle.asn1.cmc.CertificationRequest;
	using TaggedCertificationRequest = org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
	using TaggedRequest = org.bouncycastle.asn1.cmc.TaggedRequest;
	using AttributeTypeAndValue = org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using CertRequest = org.bouncycastle.asn1.crmf.CertRequest;
	using CertTemplate = org.bouncycastle.asn1.crmf.CertTemplate;
	using Controls = org.bouncycastle.asn1.crmf.Controls;
	using POPOSigningKey = org.bouncycastle.asn1.crmf.POPOSigningKey;
	using POPOSigningKeyInput = org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
	using ProofOfPossession = org.bouncycastle.asn1.crmf.ProofOfPossession;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class TaggedRequestTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new TaggedRequestTest());
		}

		public override string getName()
		{
			return "TaggedRequestTest";
		}

		private static byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");


		public override void performTest()
		{
			{ // TaggedCertificationRequest
				TaggedRequest tr = new TaggedRequest(new TaggedCertificationRequest(new BodyPartID(10L), CertificationRequest.getInstance(req1))
			   );
				byte[] b = tr.getEncoded();
				TaggedRequest trResult = TaggedRequest.getInstance(b);
				isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
				isEquals("Is TCR tag", TaggedRequest.TCR, tr.getTagNo());
				isEquals("Value", tr.getValue(), trResult.getValue());
			}

			{ // CertReqMsg

				POPOSigningKeyInput pski = new POPOSigningKeyInput(new GeneralName(GeneralName.rfc822Name, "fish"), new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.certBag, new ASN1Integer(5L)), new ASN1Integer(4L)
				   ));

				AlgorithmIdentifier aid = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.crlTypes, new ASN1Integer(1L));
				DERBitString dbi = new DERBitString(2);

				POPOSigningKey popoSigningKey = new POPOSigningKey(pski, aid, dbi);
				ProofOfPossession proofOfPossession = new ProofOfPossession(new POPOSigningKey(pski, aid, dbi));

				TaggedRequest tr = new TaggedRequest(new CertReqMsg(new CertRequest(new ASN1Integer(1L), CertTemplate.getInstance(new DERSequence(new DERTaggedObject(0,new ASN1Integer(3L)))), new Controls(new AttributeTypeAndValue(PKCSObjectIdentifiers_Fields.pkcs_9,new ASN1Integer(3)))), proofOfPossession, new AttributeTypeAndValue[0])
			   );
				byte[] b = tr.getEncoded();
				TaggedRequest trResult = TaggedRequest.getInstance(b);
				isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
				isEquals("Is CRM tag", TaggedRequest.CRM, tr.getTagNo());
				isEquals("Value", tr.getValue(), trResult.getValue());
			}


			{ // ORM
				TaggedRequest tr = TaggedRequest.getInstance(new DERTaggedObject(TaggedRequest.ORM, new DERSequence(new ASN1Encodable[]
				{
					new BodyPartID(1L),
					PKCSObjectIdentifiers_Fields.data,
					new DERSet(new ASN1Encodable[]{new ASN1Integer(5L)})
				})));
				byte[] b = tr.getEncoded();
				TaggedRequest trResult = TaggedRequest.getInstance(b);
				isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
				isEquals("Is ORM tag", TaggedRequest.ORM, tr.getTagNo());
				isEquals("Value", tr.getValue(), trResult.getValue());
			}

		}
	}

}