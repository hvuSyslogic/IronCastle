using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using OtherMsg = org.bouncycastle.asn1.cmc.OtherMsg;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class OtherMsgTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new OtherMsgTest());
		}

		public override string getName()
		{
			return "OtherMsgTest";
		}

		public override void performTest()
		{
			OtherMsg otherMsg = new OtherMsg(new BodyPartID(10L), PKCSObjectIdentifiers_Fields.id_aa, new DERUTF8String("Cats"));
			byte[] b = otherMsg.getEncoded();
			OtherMsg otherMsgResult = OtherMsg.getInstance(b);

			isEquals("bodyPartID", otherMsg.getBodyPartID(), otherMsgResult.getBodyPartID());
			isEquals("otherMsgType", otherMsg.getOtherMsgType(), otherMsgResult.getOtherMsgType());
			isEquals("otherMsgValue", otherMsg.getOtherMsgValue(), otherMsgResult.getOtherMsgValue());

			try
			{
				OtherMsg.getInstance(new DERSequence());
				fail("Sequence should be 3 elements long.");
			}
			catch (Exception t)
			{
				isEquals("Sequence size",t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}