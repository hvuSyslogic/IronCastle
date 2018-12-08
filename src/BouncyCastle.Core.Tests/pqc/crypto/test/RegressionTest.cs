using System;

namespace org.bouncycastle.pqc.crypto.test
{
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class RegressionTest
	{
		public static Test[] tests = new Test[]
		{
			new GMSSSignerTest(),
			new McElieceFujisakiCipherTest(),
			new McElieceKobaraImaiCipherTest(),
			new McElieceCipherTest(),
			new McEliecePointchevalCipherTest(),
			new RainbowSignerTest(),
			new Sphincs256Test(),
			new NewHopeTest()
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