namespace org.bouncycastle.math.ec.test
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;

	public class FixedPointTest : TestCase
	{
		private static readonly SecureRandom RANDOM = new SecureRandom();

		private const int TESTS_PER_CURVE = 5;

		public virtual void testFixedPointMultiplier()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.math.ec.FixedPointCombMultiplier M = new org.bouncycastle.math.ec.FixedPointCombMultiplier();
			FixedPointCombMultiplier M = new FixedPointCombMultiplier();

			Set names = new HashSet(enumToList(ECNamedCurveTable.getNames()));
			names.addAll(enumToList(CustomNamedCurves.getNames()));

			Iterator it = names.iterator();
			while (it.hasNext())
			{
				string name = (string)it.next();

				X9ECParameters x9A = ECNamedCurveTable.getByName(name);
				X9ECParameters x9B = CustomNamedCurves.getByName(name);

				X9ECParameters x9 = x9B != null ? x9B : x9A;

				for (int i = 0; i < TESTS_PER_CURVE; ++i)
				{
					BigInteger k = new BigInteger(x9.getN().bitLength(), RANDOM);
					ECPoint pRef = ECAlgorithms.referenceMultiply(x9.getG(), k);

					if (x9A != null)
					{
						ECPoint pA = M.multiply(x9A.getG(), k);
						assertPointsEqual("Standard curve fixed-point failure", pRef, pA);
					}

					if (x9B != null)
					{
						ECPoint pB = M.multiply(x9B.getG(), k);
						assertPointsEqual("Custom curve fixed-point failure", pRef, pB);
					}
				}
			}
		}

		private List enumToList(Enumeration en)
		{
			List rv = new ArrayList();

			while (en.hasMoreElements())
			{
				rv.add(en.nextElement());
			}

			return rv;
		}

		private void assertPointsEqual(string message, ECPoint a, ECPoint b)
		{
			// NOTE: We intentionally test points for equality in both directions
			assertEquals(message, a, b);
			assertEquals(message, b, a);
		}

		public static Test suite()
		{
			return new TestSuite(typeof(FixedPointTest));
		}
	}

}