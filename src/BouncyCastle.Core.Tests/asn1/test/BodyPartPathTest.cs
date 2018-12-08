namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartPath = org.bouncycastle.asn1.cmc.BodyPartPath;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class BodyPartPathTest : SimpleTest
	{

		public override void performTest()
		{
			Random rand = new Random();
			{
				BodyPartID[] bpid = new BodyPartID[Math.Abs(rand.nextInt()) % 20];
				for (int t = 0; t < bpid.Length; t++)
				{
					bpid[t] = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));
				}
				BodyPartPath bpp = new BodyPartPath(bpid);
				DERSequence _bpp = (DERSequence)bpp.toASN1Primitive();
				byte[] b = bpp.getEncoded();

				//
				// Decode and compare results.
				//

				BodyPartPath resList = BodyPartPath.getInstance(b);
				DERSequence _resList = (DERSequence)resList.toASN1Primitive();

				isEquals(_bpp.size(), _resList.size());

				for (int j = 0; j < _bpp.size(); j++)
				{
					isEquals(_resList.getObjectAt(j), _bpp.getObjectAt(j));
				}
			}
			{
				//
				// Compare when same thing instantiated via different constructors.
				//

				BodyPartID bpid = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));
				BodyPartPath bpidList = new BodyPartPath(bpid); // Single entry constructor.
				BodyPartPath resList = new BodyPartPath(new BodyPartID[]{bpid}); // Array constructor.

				DERSequence _bpidList = (DERSequence)bpidList.toASN1Primitive();
				DERSequence _resList = (DERSequence)resList.toASN1Primitive();

				isEquals(_bpidList, _resList);
			}
		}

		public override string getName()
		{
			return "BodyPartPathTest";
		}

		public static void Main(string[] args)
		{
			runTest(new BodyPartPathTest());
		}

	}

}