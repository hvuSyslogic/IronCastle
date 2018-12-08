﻿using System;

namespace org.bouncycastle.crypto.test
{

	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// SHA3 Digest Test
	/// </summary>
	public class SHA3DigestTest : SimpleTest
	{
		public class MySHA3Digest : SHA3Digest
		{
			public MySHA3Digest(int bitLength) : base(bitLength)
			{
			}

			public virtual int myDoFinal(byte[] @out, int outOff, byte partialByte, int partialBits)
			{
				return doFinal(@out, outOff, partialByte, partialBits);
			}
		}

		public SHA3DigestTest()
		{
		}

		public override string getName()
		{
			return "SHA-3";
		}

		public override void performTest()
		{
			testVectors();
		}

		public virtual void testVectors()
		{
			BufferedReader r = new BufferedReader(new InputStreamReader(this.GetType().getResourceAsStream("SHA3TestVectors.txt")));

			string line;
			while (null != (line = readLine(r)))
			{
				if (line.Length != 0)
				{
					TestVector v = readTestVector(r, line);
					runTestVector(v);
				}
			}

			r.close();
		}

		private MySHA3Digest createDigest(string algorithm)
		{
			if (algorithm.StartsWith("SHA3-", StringComparison.Ordinal))
			{
				int bits = parseDecimal(algorithm.Substring("SHA3-".Length));
				return new MySHA3Digest(bits);
			}
			throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
		}

		private byte[] decodeBinary(string block)
		{
			int bits = block.Length;
			int fullBytes = bits / 8;
			int totalBytes = (bits + 7) / 8;
			byte[] result = new byte[totalBytes];

			for (int i = 0; i < fullBytes; ++i)
			{
				string byteStr = reverse(block.Substring(i * 8, ((i + 1) * 8) - (i * 8)));
				result[i] = (byte)parseBinary(byteStr);
			}

			if (totalBytes > fullBytes)
			{
				string byteStr = reverse(block.Substring(fullBytes * 8));
				result[fullBytes] = (byte)parseBinary(byteStr);
			}

			return result;
		}

		private int parseBinary(string s)
		{
			return Convert.ToInt32(s, 2);
		}

		private int parseDecimal(string s)
		{
			return int.Parse(s);
		}

		private string readBlock(BufferedReader r)
		{
			StringBuffer b = new StringBuffer();
			string line;
			while (!string.ReferenceEquals((line = readBlockLine(r)), null))
			{
				b.append(line);
			}
			return b.ToString();
		}

		private string readBlockLine(BufferedReader r)
		{
			string line = readLine(r);
			if (string.ReferenceEquals(line, null) || line.Length == 0)
			{
				return null;
			}

			char[] chars = line.ToCharArray();

			int pos = 0;
			for (int i = 0; i != chars.Length; i++)
			{
				if (chars[i] != ' ')
				{
					chars[pos++] = chars[i];
				}
			}

			return new string(chars, 0, pos);
		}

		private TestVector readTestVector(BufferedReader r, string header)
		{
			string[] parts = splitAround(header, TestVector.SAMPLE_OF);

			string algorithm = parts[0];
			int bits = parseDecimal(stripFromChar(parts[1], '-'));

			skipUntil(r, TestVector.MSG_HEADER);
			string messageBlock = readBlock(r);
			if (messageBlock.Length != bits)
			{
				throw new IllegalStateException("Test vector length mismatch");
			}
			byte[] message = decodeBinary(messageBlock);

			skipUntil(r, TestVector.HASH_HEADER);
			byte[] hash = Hex.decode(readBlock(r));

			return new TestVector(algorithm, bits, message, hash);
		}

		private string readLine(BufferedReader r)
		{
			string line = r.readLine();
			return string.ReferenceEquals(line, null) ? null : stripFromChar(line, '#').Trim();
		}

		private string requireLine(BufferedReader r)
		{
			string line = readLine(r);
			if (string.ReferenceEquals(line, null))
			{
				throw new EOFException();
			}
			return line;
		}

		private string reverse(string s)
		{
			return (new StringBuffer(s)).reverse().ToString();
		}

		private void runTestVector(TestVector v)
		{
			int bits = v.getBits();
			int partialBits = bits % 8;

	//        JavaSystem.@out.println(v.getAlgorithm() + " " + bits + "-bit");
	//        JavaSystem.@out.println(Hex.toHexString(v.getMessage()).toUpperCase());
	//        JavaSystem.@out.println(Hex.toHexString(v.getHash()).toUpperCase());

			MySHA3Digest d = createDigest(v.getAlgorithm());
			byte[] output = new byte[d.getDigestSize()];

			byte[] m = v.getMessage();
			if (partialBits == 0)
			{
				d.update(m, 0, m.Length);
				d.doFinal(output, 0);
			}
			else
			{
				d.update(m, 0, m.Length - 1);
				d.myDoFinal(output, 0, m[m.Length - 1], partialBits);
			}

			if (!Arrays.areEqual(v.getHash(), output))
			{
				fail(v.getAlgorithm() + " " + v.getBits() + "-bit test vector hash mismatch");
	//            JavaSystem.err.println(v.getAlgorithm() + " " + v.getBits() + "-bit test vector hash mismatch");
	//            JavaSystem.err.println(Hex.toHexString(output).toUpperCase());
			}
		}

		private void skipUntil(BufferedReader r, string header)
		{
			string line;
			do
			{
				line = requireLine(r);
			} while (line.Length == 0);
			if (!line.Equals(header))
			{
				throw new IOException("Expected: " + header);
			}
		}

		private string[] splitAround(string s, string separator)
		{
			List strings = new ArrayList();

			string remaining = s;
			int index;

			while ((index = remaining.IndexOf(separator, StringComparison.Ordinal)) > 0)
			{
				strings.add(remaining.Substring(0, index));
				remaining = remaining.Substring(index + separator.Length);
			}
			strings.add(remaining);

			return (string[])strings.toArray(new string[strings.size()]);
		}

		private string stripFromChar(string s, char c)
		{
			int i = s.IndexOf(c);
			if (i >= 0)
			{
				s = s.Substring(0, i);
			}
			return s;
		}

		public static void Main(string[] args)
		{
			runTest(new SHA3DigestTest());
		}

		public class TestVector
		{
			internal static string SAMPLE_OF = " sample of ";
			internal static string MSG_HEADER = "Msg as bit string";
			internal static string HASH_HEADER = "Hash val is";

			internal string algorithm;
			internal int bits;
			internal byte[] message;
			internal byte[] hash;

			public TestVector(string algorithm, int bits, byte[] message, byte[] hash)
			{
				this.algorithm = algorithm;
				this.bits = bits;
				this.message = message;
				this.hash = hash;
			}

			public virtual string getAlgorithm()
			{
				return algorithm;
			}

			public virtual int getBits()
			{
				return bits;
			}

			public virtual byte[] getMessage()
			{
				return message;
			}

			public virtual byte[] getHash()
			{
				return hash;
			}
		}
	}

}