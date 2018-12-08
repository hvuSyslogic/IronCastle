namespace org.bouncycastle.asn1.test
{

	using PolicyConstraints = org.bouncycastle.asn1.x509.PolicyConstraints;
	using Arrays = org.bouncycastle.util.Arrays;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PolicyConstraintsTest : SimpleTest
	{
		public override string getName()
		{
			return "PolicyConstraints";
		}

		public override void performTest()
		{
			PolicyConstraints constraints = new PolicyConstraints(BigInteger.valueOf(1), BigInteger.valueOf(2));

			PolicyConstraints c = PolicyConstraints.getInstance(constraints.getEncoded());

			isTrue("1 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping().Equals(BigInteger.valueOf(1)));
			isTrue("2 inhibitPolicyMapping", c.getInhibitPolicyMapping().Equals(BigInteger.valueOf(2)));

			constraints = new PolicyConstraints(BigInteger.valueOf(3), null);

			c = PolicyConstraints.getInstance(constraints.getEncoded());

			isTrue("3 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping().Equals(BigInteger.valueOf(3)));
			isTrue("4 inhibitPolicyMapping", c.getInhibitPolicyMapping() == null);


			constraints = new PolicyConstraints(null, BigInteger.valueOf(4));

			c = PolicyConstraints.getInstance(constraints.getEncoded());

			isTrue("5 inhibitPolicyMapping", c.getInhibitPolicyMapping().Equals(BigInteger.valueOf(4)));
			isTrue("6 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping() == null);

			isTrue("encoding test", Arrays.areEqual((new PolicyConstraints(BigInteger.valueOf(1), null)).getEncoded(), (new DERSequence(new DERTaggedObject(false, 0, new ASN1Integer(1)))).getEncoded()));
		}

		public static void Main(string[] args)
		{
			runTest(new PolicyConstraintsTest());
		}
	}

}