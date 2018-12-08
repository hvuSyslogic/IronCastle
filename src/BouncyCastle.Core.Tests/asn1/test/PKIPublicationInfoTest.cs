namespace org.bouncycastle.asn1.test
{

	using PKIPublicationInfo = org.bouncycastle.asn1.crmf.PKIPublicationInfo;
	using SinglePubInfo = org.bouncycastle.asn1.crmf.SinglePubInfo;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PKIPublicationInfoTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PKIPublicationInfoTest());
		}

		public override string getName()
		{
			return "PKIPublicationInfoTest";
		}

		public override void performTest()
		{
			PKIPublicationInfo pkiPubInfo = new PKIPublicationInfo(PKIPublicationInfo.dontPublish);

			isEquals(PKIPublicationInfo.dontPublish, pkiPubInfo.getAction());

			encEqualTest(pkiPubInfo);

			pkiPubInfo = new PKIPublicationInfo(PKIPublicationInfo.dontPublish.getValue());

			isEquals(PKIPublicationInfo.dontPublish, pkiPubInfo.getAction());

			encEqualTest(pkiPubInfo);

			SinglePubInfo singlePubInfo1 = new SinglePubInfo(SinglePubInfo.x500, new GeneralName(new X500Name("CN=TEST")));
			pkiPubInfo = new PKIPublicationInfo(singlePubInfo1);

			isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
			isEquals(1, pkiPubInfo.getPubInfos().Length);
			isEquals(singlePubInfo1, pkiPubInfo.getPubInfos()[0]);

			encEqualTest(pkiPubInfo);

			SinglePubInfo singlePubInfo2 = new SinglePubInfo(SinglePubInfo.x500, new GeneralName(new X500Name("CN=BLOOT")));

			pkiPubInfo = new PKIPublicationInfo(new SinglePubInfo[] {singlePubInfo1, singlePubInfo2});

			isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
			isEquals(2, pkiPubInfo.getPubInfos().Length);
			isEquals(singlePubInfo1, pkiPubInfo.getPubInfos()[0]);
			isEquals(singlePubInfo2, pkiPubInfo.getPubInfos()[1]);

			encEqualTest(pkiPubInfo);

			pkiPubInfo = new PKIPublicationInfo((SinglePubInfo)null);

			isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
			isTrue(null == pkiPubInfo.getPubInfos());

			encEqualTest(pkiPubInfo);

			pkiPubInfo = new PKIPublicationInfo((SinglePubInfo[])null);

			isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
			isTrue(null == pkiPubInfo.getPubInfos());

			encEqualTest(pkiPubInfo);
		}

		private void encEqualTest(PKIPublicationInfo pubInfo)
		{
			byte[] b = pubInfo.getEncoded();

			PKIPublicationInfo pubInfoResult = PKIPublicationInfo.getInstance(b);

			isEquals(pubInfo, pubInfoResult);
		}
	}

}