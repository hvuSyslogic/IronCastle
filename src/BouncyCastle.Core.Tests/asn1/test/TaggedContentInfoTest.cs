using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using TaggedContentInfo = org.bouncycastle.asn1.cmc.TaggedContentInfo;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class TaggedContentInfoTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new TaggedContentInfoTest());
		}

		public override string getName()
		{
			return "TaggedContentInfoTest";
		}

		public override void performTest()
		{
			TaggedContentInfo tci = new TaggedContentInfo(new BodyPartID(10L), new ContentInfo(PKCSObjectIdentifiers_Fields.pkcs_9_at_contentType, new DERUTF8String("Cats")));

			byte[] b = tci.getEncoded();

			TaggedContentInfo tciResp = TaggedContentInfo.getInstance(b);

			isEquals("bodyPartID", tci.getBodyPartID(), tciResp.getBodyPartID());
			isEquals("contentInfo", tci.getContentInfo(), tciResp.getContentInfo());

			try
			{
				TaggedContentInfo.getInstance(new DERSequence());
				fail("Sequence must be 2");
			}
			catch (Exception t)
			{
				isEquals("Exception type", t.GetType(), typeof(IllegalArgumentException));
			}

		}
	}

}