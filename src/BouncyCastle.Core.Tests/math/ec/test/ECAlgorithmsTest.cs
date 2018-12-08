namespace org.bouncycastle.math.ec.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;

	public class ECAlgorithmsTest : TestCase
	{
		private const int SCALE = 4;
		private static readonly SecureRandom RND = new SecureRandom();

		public virtual void testSumOfMultiplies()
		{
			X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
			assertNotNull(x9);
			doTestSumOfMultiplies(x9);
		}

		// TODO Ideally, mark this test not to run by default
		public virtual void testSumOfMultipliesComplete()
		{
			ArrayList x9s = getTestCurves();
			Iterator it = x9s.iterator();
			while (it.hasNext())
			{
				X9ECParameters x9 = (X9ECParameters)it.next();
				doTestSumOfMultiplies(x9);
			}
		}

		public virtual void testSumOfTwoMultiplies()
		{
			X9ECParameters x9 = CustomNamedCurves.getByName("secp256r1");
			assertNotNull(x9);
			doTestSumOfTwoMultiplies(x9);
		}

		// TODO Ideally, mark this test not to run by default
		public virtual void testSumOfTwoMultipliesComplete()
		{
			ArrayList x9s = getTestCurves();
			Iterator it = x9s.iterator();
			while (it.hasNext())
			{
				X9ECParameters x9 = (X9ECParameters)it.next();
				doTestSumOfTwoMultiplies(x9);
			}
		}

		private void doTestSumOfMultiplies(X9ECParameters x9)
		{
			ECPoint[] points = new ECPoint[SCALE];
			BigInteger[] scalars = new BigInteger[SCALE];
			for (int i = 0; i < SCALE; ++i)
			{
				points[i] = getRandomPoint(x9);
				scalars[i] = getRandomScalar(x9);
			}

			ECPoint u = x9.getCurve().getInfinity();
			for (int i = 0; i < SCALE; ++i)
			{
				u = u.add(points[i].multiply(scalars[i]));

				ECPoint v = ECAlgorithms.sumOfMultiplies(copyPoints(points, i + 1), copyScalars(scalars, i + 1));

				ECPoint[] results = new ECPoint[]{u, v};
				x9.getCurve().normalizeAll(results);

				assertPointsEqual("ECAlgorithms.sumOfMultiplies is incorrect", results[0], results[1]);
			}
		}

		private void doTestSumOfTwoMultiplies(X9ECParameters x9)
		{
			ECPoint p = getRandomPoint(x9);
			BigInteger a = getRandomScalar(x9);

			for (int i = 0; i < SCALE; ++i)
			{
				ECPoint q = getRandomPoint(x9);
				BigInteger b = getRandomScalar(x9);

				ECPoint u = p.multiply(a).add(q.multiply(b));
				ECPoint v = ECAlgorithms.shamirsTrick(p, a, q, b);
				ECPoint w = ECAlgorithms.sumOfTwoMultiplies(p, a, q, b);

				ECPoint[] results = new ECPoint[]{u, v, w};
				x9.getCurve().normalizeAll(results);

				assertPointsEqual("ECAlgorithms.shamirsTrick is incorrect", results[0], results[1]);
				assertPointsEqual("ECAlgorithms.sumOfTwoMultiplies is incorrect", results[0], results[2]);

				p = q;
				a = b;
			}
		}

		private void assertPointsEqual(string message, ECPoint a, ECPoint b)
		{
			assertEquals(message, a, b);
		}

		private ECPoint[] copyPoints(ECPoint[] ps, int len)
		{
			ECPoint[] result = new ECPoint[len];
			JavaSystem.arraycopy(ps, 0, result, 0, len);
			return result;
		}

		private BigInteger[] copyScalars(BigInteger[] ks, int len)
		{
			BigInteger[] result = new BigInteger[len];
			JavaSystem.arraycopy(ks, 0, result, 0, len);
			return result;
		}

		private ECPoint getRandomPoint(X9ECParameters x9)
		{
			return x9.getG().multiply(getRandomScalar(x9));
		}

		private BigInteger getRandomScalar(X9ECParameters x9)
		{
			return new BigInteger(x9.getN().bitLength(), RND);
		}

		private ArrayList getTestCurves()
		{
			ArrayList x9s = new ArrayList();
			Set names = new HashSet(AllTests.enumToList(ECNamedCurveTable.getNames()));
			names.addAll(AllTests.enumToList(CustomNamedCurves.getNames()));

			Iterator it = names.iterator();
			while (it.hasNext())
			{
				string name = (string)it.next();

				X9ECParameters x9 = ECNamedCurveTable.getByName(name);
				if (x9 != null)
				{
					addTestCurves(x9s, x9);
				}

				x9 = CustomNamedCurves.getByName(name);
				if (x9 != null)
				{
					addTestCurves(x9s, x9);
				}
			}
			return x9s;
		}

		private void addTestCurves(ArrayList x9s, X9ECParameters x9)
		{
			ECCurve curve = x9.getCurve();

			int[] coords = ECCurve.getAllCoordinateSystems();
			for (int i = 0; i < coords.Length; ++i)
			{
				int coord = coords[i];
				if (curve.getCoordinateSystem() == coord)
				{
					x9s.add(x9);
				}
				else if (curve.supportsCoordinateSystem(coord))
				{
					ECCurve c = curve.configure().setCoordinateSystem(coord).create();
					x9s.add(new X9ECParameters(c, c.importPoint(x9.getG()), x9.getN(), x9.getH()));
				}
			}
		}

		public static Test suite()
		{
			return new TestSuite(typeof(ECAlgorithmsTest));
		}

	}

}