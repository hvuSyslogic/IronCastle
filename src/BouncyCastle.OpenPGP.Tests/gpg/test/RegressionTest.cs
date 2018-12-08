using org.bouncycastle.jce.provider;

using System;

namespace org.bouncycastle.gpg.test
{

	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class RegressionTest
	{
		public static Test[] tests = new Test[] {new KeyBoxTest()};

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			for (int i = 0; i != tests.Length; i++)
			{
				TestResult result = tests[i].perform();
				JavaSystem.@out.println(result);
				if (result.getException() != null)
				{
					Console.WriteLine(result.getException().ToString());
					Console.Write(result.getException().StackTrace);
				}
			}
		}
	}


}