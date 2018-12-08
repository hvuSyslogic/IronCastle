using System;

namespace org.bouncycastle.crypto.test
{

	using HC128Engine = org.bouncycastle.crypto.engines.HC128Engine;
	using HC256Engine = org.bouncycastle.crypto.engines.HC256Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// HC-128 and HC-256 Tests. Based on the test vectors in the official reference
	/// papers, respectively:
	/// 
	/// http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
	/// http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
	/// </summary>
	public class HCFamilyVecTest : SimpleTest
	{
		public class PeekableLineReader : BufferedReader
		{
			public PeekableLineReader(Reader r) : base(r)
			{

				peek = base.readLine();
			}

			public virtual string peekLine()
			{
				return peek;
			}

			public virtual string readLine()
			{
				string tmp = peek;
				peek = base.readLine();
				return tmp;
			}

			internal string peek;
		}

		public override string getName()
		{
			return "HC-128 and HC-256 (ecrypt)";
		}

		public override void performTest()
		{
			runTests(new HC128Engine(), "ecrypt_HC-128.txt");
			runTests(new HC256Engine(), "ecrypt_HC-256_128K_128IV.txt");
			runTests(new HC256Engine(), "ecrypt_HC-256_256K_128IV.txt");
			runTests(new HC256Engine(), "ecrypt_HC-256_128K_256IV.txt");
			runTests(new HC256Engine(), "ecrypt_HC-256_256K_256IV.txt");
		}

		private void runTests(StreamCipher hc, string fileName)
		{
			Reader resource = new InputStreamReader(this.GetType().getResourceAsStream(fileName));
			PeekableLineReader r = new PeekableLineReader(resource);
			runAllVectors(hc, fileName, r);
		}

		private void runAllVectors(StreamCipher hc, string fileName, PeekableLineReader r)
		{
			for (;;)
			{
				string line = r.readLine();
				if (string.ReferenceEquals(line, null))
				{
					break;
				}

				line = line.Trim();

				if (line.StartsWith("Set ", StringComparison.Ordinal))
				{
					runVector(hc, fileName, r, dellChar(line, ':'));
				}
			}
		}

		private string dellChar(string s, char c)
		{
			StringBuffer b = new StringBuffer();

			for (int i = 0; i != s.Length; i++)
			{
				if (s[i] != c)
				{
					b.append(s[i]);
				}
			}

			return b.ToString();
		}

		private void runVector(StreamCipher hc, string fileName, PeekableLineReader r, string vectorName)
		{
	//        JavaSystem.@out.println(fileName + " => " + vectorName);
			string hexKey = readBlock(r);
			string hexIV = readBlock(r);

			CipherParameters cp = new KeyParameter(Hex.decode(hexKey));
			cp = new ParametersWithIV(cp, Hex.decode(hexIV));
			hc.init(true, cp);

			byte[] input = new byte[64];
			byte[] output = new byte[64];
			byte[] digest = new byte[64];
			int pos = 0;

			for (;;)
			{
				string line1 = r.peekLine().Trim();
				int equalsPos = line1.IndexOf('=');
				string lead = line1.Substring(0, equalsPos - 1);

				string hexData = readBlock(r);
				byte[] data = Hex.decode(hexData);

				if (lead.Equals("xor-digest"))
				{
					if (!Arrays.areEqual(data, digest))
					{
						fail("Failed in " + fileName + " for test vector: " + vectorName + " at " + lead);
	//                  JavaSystem.@out.println(fileName + " => " + vectorName + " failed at " + lead); return;
					}
					break;
				}

				int posA = lead.IndexOf('[');
				int posB = lead.IndexOf("..", StringComparison.Ordinal);
				int posC = lead.IndexOf(']');
				int start = int.Parse(lead.Substring(posA + 1, posB - (posA + 1)));
				int end = int.Parse(lead.Substring(posB + 2, posC - (posB + 2)));

				if (start % 64 != 0 || (end - start != 63))
				{
					throw new IllegalStateException(vectorName + ": " + lead + " not on 64 byte boundaries");
				}

				while (pos < end)
				{
					hc.processBytes(input, 0, input.Length, output, 0);
					xor(digest, output);
					pos += 64;
				}

				if (!Arrays.areEqual(data, output))
				{
					fail("Failed in " + fileName + " for test vector: " + vectorName + " at " + lead);
	//              JavaSystem.@out.println(fileName + " => " + vectorName + " failed at " + lead); return;
				}
			}
		}

		private static string readBlock(PeekableLineReader r)
		{
			string first = r.readLine().Trim();
			string result = first.Substring(first.LastIndexOf(' ') + 1);

			for (;;)
			{
				string peek = r.peekLine().Trim();
				if (peek.Length < 1 || peek.IndexOf('=') >= 0)
				{
					break;
				}
				result += r.readLine().Trim();
			}

			return result;
		}

		private static void xor(byte[] digest, byte[] block)
		{
			for (int i = 0; i < digest.Length; ++i)
			{
				digest[i] ^= block[i];
			}
		}

		public static void Main(string[] args)
		{
			runTest(new HCFamilyVecTest());
		}
	}

}