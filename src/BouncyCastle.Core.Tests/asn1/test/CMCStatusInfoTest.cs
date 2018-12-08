using System;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CMCFailInfo = org.bouncycastle.asn1.cmc.CMCFailInfo;
	using CMCStatus = org.bouncycastle.asn1.cmc.CMCStatus;
	using CMCStatusInfo = org.bouncycastle.asn1.cmc.CMCStatusInfo;
	using CMCStatusInfoBuilder = org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder;
	using PendInfo = org.bouncycastle.asn1.cmc.PendInfo;
	using Strings = org.bouncycastle.util.Strings;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class CMCStatusInfoTest : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new CMCStatusInfoTest());
		}

		public override string getName()
		{
			return "CMCStatusInfoTest";
		}

		public override void performTest()
		{
			{ // Without optional status String

				 CMCStatusInfoBuilder bldr = new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10));

				 CMCStatusInfo cmsInfo = bldr.build();

				 isTrue("Has statusString", null == cmsInfo.getStatusString());
				 isEquals("Has other info", false, cmsInfo.hasOtherInfo());

				 byte[] b = cmsInfo.getEncoded();
				 CMCStatusInfo res = CMCStatusInfo.getInstance(b);

				 // Same
				 isEquals("CMCStatus with no optional part",cmsInfo, res);

				 isEquals("Has other info", false, res.hasOtherInfo());

			 }

			 { // Without optional other info.

				CMCStatusInfoBuilder bldr = (new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats");

				CMCStatusInfo cmsInfo = bldr.build();

				isEquals("Has other info", false, cmsInfo.hasOtherInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfo res = CMCStatusInfo.getInstance(b);

				// Same
				isEquals("CMCStatus with no optional part",cmsInfo, res);

				isEquals("Has other info", false, res.hasOtherInfo());

			}


			{ // With optional info: PendInfo
				CMCStatusInfoBuilder bldr = (new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats").setOtherInfo(new PendInfo(Strings.toByteArray("fish"), new DERGeneralizedTime(DateTime.Now)));

				CMCStatusInfo cmsInfo = bldr.build();

				isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
				isEquals("Other is NOT fail info", false, cmsInfo.getOtherInfo().isFailInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfo res = CMCStatusInfo.getInstance(b);

				isEquals("With optional info: PendInfo",cmsInfo, res);

				isEquals("Must have other info", true, res.hasOtherInfo());
				isEquals("Other is NOT fail info", false, res.getOtherInfo().isFailInfo());
			}


			{ // With optional info: CMCFailInfo
				CMCStatusInfoBuilder bldr = (new CMCStatusInfoBuilder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats").setOtherInfo(CMCFailInfo.authDataFail);

				CMCStatusInfo cmsInfo = bldr.build();

				isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
				isEquals("Other is fail info", true, cmsInfo.getOtherInfo().isFailInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfo res = CMCStatusInfo.getInstance(b);

				isEquals("With optional info: CMCFailInfo",cmsInfo, res);

				isEquals("Must have other info", true, res.hasOtherInfo());
				isEquals("Other is fail info", true, res.getOtherInfo().isFailInfo());
			}

		}
	}

}