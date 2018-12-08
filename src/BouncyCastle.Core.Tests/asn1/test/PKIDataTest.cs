using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CertificationRequest = org.bouncycastle.asn1.cmc.CertificationRequest;
	using OtherMsg = org.bouncycastle.asn1.cmc.OtherMsg;
	using PKIData = org.bouncycastle.asn1.cmc.PKIData;
	using TaggedAttribute = org.bouncycastle.asn1.cmc.TaggedAttribute;
	using TaggedCertificationRequest = org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
	using TaggedContentInfo = org.bouncycastle.asn1.cmc.TaggedContentInfo;
	using TaggedRequest = org.bouncycastle.asn1.cmc.TaggedRequest;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PKIDataTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PKIDataTest());
		}

		public override string getName()
		{
			return "PKIDataTest";
		}

		public override void performTest()
		{

			byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");


			PKIData pkiData = new PKIData(new TaggedAttribute[]{new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers_Fields.id_aa, new DERSet())}, new TaggedRequest[]{new TaggedRequest(new TaggedCertificationRequest(new BodyPartID(10L), CertificationRequest.getInstance(req1)))}, new TaggedContentInfo[]{new TaggedContentInfo(new BodyPartID(10L), new ContentInfo(PKCSObjectIdentifiers_Fields.id_aa_ets_commitmentType, new ASN1Integer(10L)))}, new OtherMsg[]{new OtherMsg(new BodyPartID(10L), PKCSObjectIdentifiers_Fields.pkcs_9, new ASN1Integer(10L))});


			byte[] b = pkiData.getEncoded();

			PKIData pkiDataResult = PKIData.getInstance(b);

			isTrue("controlSequence", Arrays.areEqual(pkiData.getControlSequence(), pkiDataResult.getControlSequence()));
			isTrue("reqSequence", Arrays.areEqual(pkiData.getReqSequence(), pkiDataResult.getReqSequence()));
			isTrue("cmsSequence", Arrays.areEqual(pkiData.getCmsSequence(), pkiDataResult.getCmsSequence()));
			isTrue("otherMsgSequence", Arrays.areEqual(pkiData.getOtherMsgSequence(), pkiDataResult.getOtherMsgSequence()));

			try
			{
				PKIData.getInstance(new DERSequence());
				fail("Sequence must be 4.");
			}
			catch (Exception t)
			{
				isEquals("Exception type", t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}