namespace org.bouncycastle.asn1.test
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using ReasonFlags = org.bouncycastle.asn1.x509.ReasonFlags;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class IssuingDistributionPointUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "IssuingDistributionPoint";
		}

		public override void performTest()
		{
			DistributionPointName name = new DistributionPointName(new GeneralNames(new GeneralName(new X500Name("cn=test"))));
			ReasonFlags reasonFlags = new ReasonFlags(ReasonFlags.cACompromise);

			checkPoint(6, name, true, true, reasonFlags, true, true);

			checkPoint(2, name, false, false, reasonFlags, false, false);

			checkPoint(0, null, false, false, null, false, false);

			try
			{
				IssuingDistributionPoint.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkPoint(int size, DistributionPointName distributionPoint, bool onlyContainsUserCerts, bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL, bool onlyContainsAttributeCerts)
		{
			IssuingDistributionPoint point = new IssuingDistributionPoint(distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);

			checkValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);

			ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(point.getEncoded()));

			if (seq.size() != size)
			{
				fail("size mismatch");
			}

			point = IssuingDistributionPoint.getInstance(seq);

			checkValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);
		}

		private void checkValues(IssuingDistributionPoint point, DistributionPointName distributionPoint, bool onlyContainsUserCerts, bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL, bool onlyContainsAttributeCerts)
		{
			if (point.onlyContainsUserCerts() != onlyContainsUserCerts)
			{
				fail("mismatch on onlyContainsUserCerts");
			}

			if (point.onlyContainsCACerts() != onlyContainsCACerts)
			{
				fail("mismatch on onlyContainsCACerts");
			}

			if (point.isIndirectCRL() != indirectCRL)
			{
				fail("mismatch on indirectCRL");
			}

			if (point.onlyContainsAttributeCerts() != onlyContainsAttributeCerts)
			{
				fail("mismatch on onlyContainsAttributeCerts");
			}

			if (!isEquiv(onlySomeReasons, point.getOnlySomeReasons()))
			{
				fail("mismatch on onlySomeReasons");
			}

			if (!isEquiv(distributionPoint, point.getDistributionPoint()))
			{
				fail("mismatch on distributionPoint");
			}
		}

		private bool isEquiv(object o1, object o2)
		{
			if (o1 == null)
			{
				return o2 == null;
			}

			return o1.Equals(o2);
		}

		public static void Main(string[] args)
		{
			runTest(new IssuingDistributionPointUnitTest());
		}
	}
}