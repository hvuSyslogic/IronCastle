using System;

namespace org.bouncycastle.crypto.prng.test
{
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class RegressionTest
	{
		public static Test[] tests = new Test[]
		{
			new CTRDRBGTest(),
			new DualECDRBGTest(),
			new HashDRBGTest(),
			new HMacDRBGTest(),
			new SP800RandomTest(),
			new X931Test(),
			new FixedSecureRandomTest()
		};

		public static void Main(string[] args)
		{
			for (int i = 0; i != tests.Length; i++)
			{
				TestResult result = tests[i].perform();

				if (result.getException() != null)
				{
					Console.WriteLine(result.getException().ToString());
					Console.Write(result.getException().StackTrace);
				}

				JavaSystem.@out.println(result);
			}
		}
	}


}