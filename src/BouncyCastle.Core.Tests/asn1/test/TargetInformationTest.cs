namespace org.bouncycastle.asn1.test
{
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using Target = org.bouncycastle.asn1.x509.Target;
	using TargetInformation = org.bouncycastle.asn1.x509.TargetInformation;
	using Targets = org.bouncycastle.asn1.x509.Targets;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class TargetInformationTest : SimpleTest
	{

		public override string getName()
		{
			return "TargetInformation";
		}

		public override void performTest()
		{
			Target[] targets = new Target[2];
			Target targetName = new Target(Target.targetName, new GeneralName(GeneralName.dNSName, "www.test.com"));
			Target targetGroup = new Target(Target.targetGroup, new GeneralName(GeneralName.directoryName, "o=Test, ou=Test"));
			targets[0] = targetName;
			targets[1] = targetGroup;
			Targets targetss = new Targets(targets);
			TargetInformation targetInformation1 = new TargetInformation(targetss);
			// use an Target array
			TargetInformation targetInformation2 = new TargetInformation(targets);
			// targetInformation1 and targetInformation2 must have same
			// encoding.
			if (!targetInformation1.Equals(targetInformation2))
			{
				fail("targetInformation1 and targetInformation2 should have the same encoding.");
			}
			TargetInformation targetInformation3 = TargetInformation.getInstance(targetInformation1);
			TargetInformation targetInformation4 = TargetInformation.getInstance(targetInformation2);
			if (!targetInformation3.Equals(targetInformation4))
			{
				fail("targetInformation3 and targetInformation4 should have the same encoding.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new TargetInformationTest());
		}
	}


}