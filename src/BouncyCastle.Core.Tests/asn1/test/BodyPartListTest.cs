namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartList = org.bouncycastle.asn1.cmc.BodyPartList;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// Test the creation of BodyPartListTest and encoding and decoding.
	/// </summary>
	public class BodyPartListTest : SimpleTest
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
				BodyPartList bpl = new BodyPartList(bpid);
				DERSequence _bpl = (DERSequence)bpl.toASN1Primitive();
				byte[] b = bpl.getEncoded();

				//
				// Decode and compare results.
				//

				BodyPartList resList = BodyPartList.getInstance(b);
				DERSequence _resList = (DERSequence)resList.toASN1Primitive();

				isEquals(_bpl.size(), _resList.size());

				for (int j = 0; j < _bpl.size(); j++)
				{
					isEquals(_resList.getObjectAt(j), _bpl.getObjectAt(j));
				}
			}
			{
				//
				// Compare when same thing instantiated via different constructors.
				//

				BodyPartID bpid = new BodyPartID(Math.Abs(rand.nextLong() % 4294967295L));
				BodyPartList bpidList = new BodyPartList(bpid); // Single entry constructor.
				BodyPartList resList = new BodyPartList(new BodyPartID[]{bpid}); // Array constructor.

				DERSequence _bpidList = (DERSequence)bpidList.toASN1Primitive();
				DERSequence _resList = (DERSequence)resList.toASN1Primitive();

				isEquals(_bpidList, _resList);
			}
		}

		public override string getName()
		{
			return "BodyPartListTest";
		}

		public static void Main(string[] args)
		{
			runTest(new BodyPartListTest());
		}
	}

}