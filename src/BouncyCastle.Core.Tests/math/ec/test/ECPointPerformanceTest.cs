namespace org.bouncycastle.math.ec.test
{

	using TestCase = junit.framework.TestCase;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using Times = org.bouncycastle.util.Times;

	/// <summary>
	/// Compares the performance of the the window NAF point multiplication against conventional point
	/// multiplication.
	/// </summary>
	public class ECPointPerformanceTest : TestCase
	{
		internal const int MILLIS_PER_ROUND = 200;
		internal const int MILLIS_WARMUP = 1000;

		internal const int MULTS_PER_CHECK = 16;
		internal const int NUM_ROUNDS = 10;

		private static string[] COORD_NAMES = new string[]{"AFFINE", "HOMOGENEOUS", "JACOBIAN", "JACOBIAN-CHUDNOVSKY", "JACOBIAN-MODIFIED", "LAMBDA-AFFINE", "LAMBDA-PROJECTIVE", "SKEWED"};

		private void randMult(string curveName)
		{
			X9ECParameters spec = ECNamedCurveTable.getByName(curveName);
			if (spec != null)
			{
				randMult(curveName, spec);
			}

			spec = CustomNamedCurves.getByName(curveName);
			if (spec != null)
			{
				randMult(curveName + " (custom)", spec);
			}
		}

		private void randMult(string label, X9ECParameters spec)
		{
			ECCurve C = spec.getCurve();
			ECPoint G = (ECPoint)spec.getG();
			BigInteger n = spec.getN();

			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			random.setSeed(System.currentTimeMillis());

			JavaSystem.@out.println(label);

			int[] coords = ECCurve.getAllCoordinateSystems();
			for (int i = 0; i < coords.Length; ++i)
			{
				int coord = coords[i];
				if (C.supportsCoordinateSystem(coord))
				{
					ECCurve c = C;
					ECPoint g = G;

					bool defaultCoord = (c.getCoordinateSystem() == coord);
					if (!defaultCoord)
					{
						c = C.configure().setCoordinateSystem(coord).create();
						g = c.importPoint(G);
					}

					double avgRate = randMult(random, g, n);
					string coordName = COORD_NAMES[coord];
					StringBuffer sb = new StringBuffer();
					sb.append("   ");
					sb.append(defaultCoord ? '*' : ' ');
					sb.append(coordName);
					for (int j = sb.length(); j < 30; ++j)
					{
						sb.append(' ');
					}
					sb.append(": ");
					sb.append(avgRate);
					sb.append(" mults/sec");
					for (int j = sb.length(); j < 64; ++j)
					{
						sb.append(' ');
					}
					sb.append('(');
					sb.append(1000.0 / avgRate);
					sb.append(" millis/mult)");
					JavaSystem.@out.println(sb.ToString());
				}
			}
		}

		private double randMult(SecureRandom random, ECPoint g, BigInteger n)
		{
			BigInteger[] ks = new BigInteger[128];
			for (int i = 0; i < ks.Length; ++i)
			{
				ks[i] = new BigInteger(n.bitLength() - 1, random);
			}

			int ki = 0;
			ECPoint p = g;

			{
				long startTime = Times.nanoTime();
				long goalTime = startTime + 1000000L * MILLIS_WARMUP;

				do
				{
					BigInteger k = ks[ki];
					p = g.multiply(k);
					if ((ki & 1) != 0)
					{
						g = p;
					}
					if (++ki == ks.Length)
					{
						ki = 0;
					}
				} while (Times.nanoTime() < goalTime);
			}

			double minRate = double.MaxValue, maxRate = double.Epsilon, totalRate = 0.0;

			for (int i = 1; i <= NUM_ROUNDS; i++)
			{
				long startTime = Times.nanoTime();
				long goalTime = startTime + 1000000L * MILLIS_PER_ROUND;
				long count = 0, endTime;

				do
				{
					++count;

					for (int j = 0; j < MULTS_PER_CHECK; ++j)
					{
						BigInteger k = ks[ki];
						p = g.multiply(k);
						if ((ki & 1) != 0)
						{
							g = p;
						}
						if (++ki == ks.Length)
						{
							ki = 0;
						}
					}

					endTime = Times.nanoTime();
				} while (endTime < goalTime);

				double roundElapsed = (double)(endTime - startTime);
				double roundRate = count * MULTS_PER_CHECK * 1000000000L / roundElapsed;

				minRate = Math.Min(minRate, roundRate);
				maxRate = Math.Max(maxRate, roundRate);
				totalRate += roundRate;
			}

			return (totalRate - minRate - maxRate) / (NUM_ROUNDS - 2);
		}

		public virtual void testMultiply()
		{
			SortedSet names = new TreeSet(AllTests.enumToList(ECNamedCurveTable.getNames()));
			names.addAll(AllTests.enumToList(CustomNamedCurves.getNames()));

			Set oids = new HashSet();

			Iterator it = names.iterator();
			while (it.hasNext())
			{
				string name = (string)it.next();
				ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);
				if (oid == null)
				{
					oid = CustomNamedCurves.getOID(name);
				}
				if (oid != null && !oids.add(oid))
				{
					continue;
				}

				randMult(name);
			}
		}
	}

}