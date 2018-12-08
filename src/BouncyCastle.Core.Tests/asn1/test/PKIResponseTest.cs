using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using OtherMsg = org.bouncycastle.asn1.cmc.OtherMsg;
	using PKIResponse = org.bouncycastle.asn1.cmc.PKIResponse;
	using TaggedAttribute = org.bouncycastle.asn1.cmc.TaggedAttribute;
	using TaggedContentInfo = org.bouncycastle.asn1.cmc.TaggedContentInfo;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PKIResponseTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PKIResponseTest());
		}

		public override string getName()
		{
			return "PKIResponseTest";
		}

		public override void performTest()
		{
			PKIResponse pkiResponse = PKIResponse.getInstance(new DERSequence(new ASN1Encodable[]
			{
				new DERSequence(new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers_Fields.bagtypes, new DERSet())),
				new DERSequence(new TaggedContentInfo(new BodyPartID(12L), new ContentInfo(PKCSObjectIdentifiers_Fields.id_aa, new ASN1Integer(10L)))),
				new DERSequence(new OtherMsg(new BodyPartID(12), PKCSObjectIdentifiers_Fields.id_aa_msgSigDigest, new DERUTF8String("foo")))
			}));

			byte[] b = pkiResponse.getEncoded();

			PKIResponse pkiResponseResult = PKIResponse.getInstance(b);

			isEquals(pkiResponse, pkiResponseResult);

		}
	}

}