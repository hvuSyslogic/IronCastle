using System;

namespace org.bouncycastle.crypto.test
{

	using SCrypt = org.bouncycastle.crypto.generators.SCrypt;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/*
	 * scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
	 * (http://www.tarsnap.com/scrypt/scrypt.pdf)
	 */
	public class SCryptTest : SimpleTest
	{
		public override string getName()
		{
			return "SCrypt";
		}

		public override void performTest()
		{
			testParameters();
			testVectors();
		}

		public virtual void testParameters()
		{
			checkOK("Minimal values", new byte[0], new byte[0], 2, 1, 1, 1);
			checkIllegal("Cost parameter must be > 1", new byte[0], new byte[0], 1, 1, 1, 1);
			checkOK("Cost parameter 32768 OK for r == 1", new byte[0], new byte[0], 32768, 1, 1, 1);
			checkIllegal("Cost parameter must < 65536 for r == 1", new byte[0], new byte[0], 65536, 1, 1, 1);
			checkIllegal("Block size must be >= 1", new byte[0], new byte[0], 2, 0, 2, 1);
			checkIllegal("Parallelisation parameter must be >= 1", new byte[0], new byte[0], 2, 1, 0, 1);
			// checkOK("Parallelisation parameter 65535 OK for r = 4", new byte[0], new byte[0], 2, 32,
			// 65535, 1);
			checkIllegal("Parallelisation parameter must be < 65535 for r = 4", new byte[0], new byte[0], 2, 32, 65536, 1);

			checkIllegal("Len parameter must be > 1", new byte[0], new byte[0], 2, 1, 1, 0);
		}

		private void checkOK(string msg, byte[] pass, byte[] salt, int N, int r, int p, int len)
		{
			try
			{
				SCrypt.generate(pass, salt, N, r, p, len);
			}
			catch (IllegalArgumentException e)
			{
				e.printStackTrace();
				fail(msg);
			}
		}

		private void checkIllegal(string msg, byte[] pass, byte[] salt, int N, int r, int p, int len)
		{
			try
			{
				SCrypt.generate(pass, salt, N, r, p, len);
				fail(msg);
			}
			catch (IllegalArgumentException)
			{
				// e.printStackTrace();
			}
		}

		public virtual void testVectors()
		{
			BufferedReader br = new BufferedReader(new InputStreamReader(this.GetType().getResourceAsStream("SCryptTestVectors.txt")));

			int count = 0;
			string line = br.readLine();

			while (!string.ReferenceEquals(line, null))
			{
				++count;
				string header = line;
				StringBuffer data = new StringBuffer();

				while (!isEndData(line = br.readLine()))
				{
					for (int i = 0; i != line.Length; i++)
					{
						if (line[i] != ' ')
						{
							data.append(line[i]);
						}
					}
				}

				int start = header.IndexOf('(') + 1;
				int limit = header.LastIndexOf(')');
				string argStr = header.Substring(start, limit - start);
				string[] args = Strings.Split(argStr, ',');

				byte[] P = extractQuotedString(args[0]);
				byte[] S = extractQuotedString(args[1]);
				int N = extractInteger(args[2]);
				int r = extractInteger(args[3]);
				int p = extractInteger(args[4]);
				int dkLen = extractInteger(args[5]);
				byte[] expected = Hex.decode(data.ToString());

				// This skips very expensive test case(s), remove check to re-enable
				if (N <= 16384)
				{
					byte[] result = SCrypt.generate(P, S, N, r, p, dkLen);

					if (!areEqual(expected, result))
					{
						fail("Result does not match expected value in test case " + count);
					}
				}
			}

			br.close();
		}

		private static bool isEndData(string line)
		{
			return string.ReferenceEquals(line, null) || line.StartsWith("scrypt", StringComparison.Ordinal);
		}

		private static byte[] extractQuotedString(string arg)
		{
			arg = arg.Trim();
			arg = arg.Substring(1, (arg.Length - 1) - 1);
			return Strings.toByteArray(arg);
		}

		private static int extractInteger(string arg)
		{
			return int.Parse(arg.Trim());
		}

		public static void Main(string[] args)
		{
			runTest(new SCryptTest());
		}
	}

}