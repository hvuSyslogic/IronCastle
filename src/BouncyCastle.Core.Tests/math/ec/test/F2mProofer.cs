using System;

namespace org.bouncycastle.math.ec.test
{

	using SECNamedCurves = org.bouncycastle.asn1.sec.SECNamedCurves;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class F2mProofer
	{
		private const int NUM_SAMPLES = 1000;

		private const string PATH = "crypto/test/src/org/bouncycastle/math/ec/test/samples/";

		private const string INPUT_FILE_NAME_PREFIX = "Input_";

		private const string RESULT_FILE_NAME_PREFIX = "Output_";

		/// <summary>
		/// The standard curves on which the tests are done
		/// </summary>
		public static readonly string[] CURVES = new string[] {"sect163r2", "sect233r1", "sect283r1", "sect409r1", "sect571r1"};

		private string pointToString(ECPoint.F2m p)
		{
			ECFieldElement.F2m x = (ECFieldElement.F2m) p.getAffineXCoord();
			ECFieldElement.F2m y = (ECFieldElement.F2m) p.getAffineYCoord();

			int m = x.getM();
			int len = m / 2 + 5;

			StringBuffer sb = new StringBuffer(len);
			sb.append('(');
			sb.append(x.toBigInteger().ToString(16));
			sb.append(", ");
			sb.append(y.toBigInteger().ToString(16));
			sb.append(')');

			return sb.ToString();
		}

		private void generateRandomInput(X9ECParameters x9ECParameters)
		{
			ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
			int m = ((ECFieldElement.F2m)(g.getAffineXCoord())).getM();

			SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
			Properties inputProps = new Properties();
			for (int i = 0; i < NUM_SAMPLES; i++)
			{
				BigInteger rand = BigIntegers.createRandomBigInteger(m, secRand);
				inputProps.put(Convert.ToString(i), rand.ToString(16));
			}
			string bits = Convert.ToString(m);
			FileOutputStream fos = new FileOutputStream(PATH + INPUT_FILE_NAME_PREFIX + bits + ".properties");
			inputProps.store(fos, "Input Samples of length" + bits);
		}

		private void multiplyPoints(X9ECParameters x9ECParameters, string classPrefix)
		{
			ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
			int m = ((ECFieldElement.F2m)(g.getAffineXCoord())).getM();

			string inputFileName = PATH + INPUT_FILE_NAME_PREFIX + m + ".properties";
			Properties inputProps = new Properties();
			inputProps.load(new FileInputStream(inputFileName));

			Properties outputProps = new Properties();

			for (int i = 0; i < NUM_SAMPLES; i++)
			{
				BigInteger rand = new BigInteger(inputProps.getProperty(Convert.ToString(i)), 16);
				ECPoint.F2m result = (ECPoint.F2m) g.multiply(rand).normalize();
				string resultStr = pointToString(result);
				outputProps.setProperty(Convert.ToString(i), resultStr);
			}

			string outputFileName = PATH + RESULT_FILE_NAME_PREFIX + classPrefix + "_" + m + ".properties";
			FileOutputStream fos = new FileOutputStream(outputFileName);
			outputProps.store(fos, "Output Samples of length" + m);
		}

		private Properties loadResults(string classPrefix, int m)
		{
			FileInputStream fis = new FileInputStream(PATH + RESULT_FILE_NAME_PREFIX + classPrefix + "_" + m + ".properties");
			Properties res = new Properties();
			res.load(fis);
			return res;

		}

		private void compareResult(X9ECParameters x9ECParameters, string classPrefix1, string classPrefix2)
		{
			ECPoint.F2m g = (ECPoint.F2m) x9ECParameters.getG();
			int m = ((ECFieldElement.F2m)(g.getAffineXCoord())).getM();

			Properties res1 = loadResults(classPrefix1, m);
			Properties res2 = loadResults(classPrefix2, m);

			Set keys = res1.keySet();
			Iterator iter = keys.iterator();
			while (iter.hasNext())
			{
				string key = (string) iter.next();
				string result1 = res1.getProperty(key);
				string result2 = res2.getProperty(key);
				if (!(result1.Equals(result2)))
				{
					JavaSystem.err.println("Difference found: m = " + m + ", " + result1 + " does not equal " + result2);
				}
			}

		}

		private static void usage()
		{
			JavaSystem.err.println("Usage: F2mProofer [-init | -multiply <className> " + "| -compare <className1> <className2>]");
		}

		public static void Main(string[] args)
		{
			if (args.Length == 0)
			{
				usage();
				return;
			}
			F2mProofer proofer = new F2mProofer();
			if (args[0].Equals("-init"))
			{
				JavaSystem.@out.println("Generating random input...");
				for (int i = 0; i < CURVES.Length; i++)
				{
					X9ECParameters x9ECParameters = SECNamedCurves.getByName(CURVES[i]);
					proofer.generateRandomInput(x9ECParameters);
				}
				JavaSystem.@out.println("Successfully generated random input in " + PATH);
			}
			else if (args[0].Equals("-compare"))
			{
				if (args.Length < 3)
				{
					usage();
					return;
				}
				string classPrefix1 = args[1];
				string classPrefix2 = args[2];
				JavaSystem.@out.println("Comparing results...");
				for (int i = 0; i < CURVES.Length; i++)
				{
					X9ECParameters x9ECParameters = SECNamedCurves.getByName(CURVES[i]);
					proofer.compareResult(x9ECParameters, classPrefix1, classPrefix2);
				}
				JavaSystem.@out.println("Successfully compared results in " + PATH);
			}
			else if (args[0].Equals("-multiply"))
			{
				if (args.Length < 2)
				{
					usage();
					return;
				}
				string classPrefix = args[1];
				JavaSystem.@out.println("Multiplying points...");
				for (int i = 0; i < CURVES.Length; i++)
				{
					X9ECParameters x9ECParameters = SECNamedCurves.getByName(CURVES[i]);
					proofer.multiplyPoints(x9ECParameters, classPrefix);
				}
				JavaSystem.@out.println("Successfully generated multiplied points in " + PATH);
			}
			else
			{
				usage();
			}
		}
	}

}