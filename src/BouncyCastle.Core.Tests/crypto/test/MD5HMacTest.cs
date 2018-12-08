using System;

namespace org.bouncycastle.crypto.test
{
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// MD5 HMac Test, test vectors from RFC 2202
	/// </summary>
	public class MD5HMacTest : SimpleTest
	{
		internal static readonly string[] keys = new string[] {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

		internal static readonly string[] digests = new string[] {"9294727a3638bb1c13f48ef8158bfc9d", "750c783e6ab0b503eaa86e310a5db738", "56be34521d144c88dbb8c733f0e8b3f6", "697eaf0aca3a3aea3a75164746ffaa79", "56461ef2342edc00f9bab995690efd4c", "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", "6f630fad67cda0ee1fb1f562db3aa53e"};

		internal static readonly string[] messages = new string[] {"Hi There", "what do ya want for nothing?", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "Test With Truncation", "Test Using Larger Than Block-Size Key - Hash Key First", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"};

		public override string getName()
		{
			return "MD5HMac";
		}

		public override void performTest()
		{
			HMac hmac = new HMac(new MD5Digest());
			byte[] resBuf = new byte[hmac.getMacSize()];

			for (int i = 0; i < messages.Length; i++)
			{
				byte[] m = messages[i].GetBytes();
				if (messages[i].StartsWith("0x", StringComparison.Ordinal))
				{
					m = Hex.decode(messages[i].Substring(2));
				}
				hmac.init(new KeyParameter(Hex.decode(keys[i])));
				hmac.update(m, 0, m.Length);
				hmac.doFinal(resBuf, 0);

				if (!areEqual(resBuf, Hex.decode(digests[i])))
				{
					fail("Vector " + i + " failed");
				}
			}

			// test reset
			int vector = 0; // vector used for test
			byte[] m = messages[vector].GetBytes();
			if (messages[vector].StartsWith("0x", StringComparison.Ordinal))
			{
				m = Hex.decode(messages[vector].Substring(2));
			}
			hmac.init(new KeyParameter(Hex.decode(keys[vector])));
			hmac.update(m, 0, m.Length);
			hmac.doFinal(resBuf, 0);
			hmac.reset();
			hmac.update(m, 0, m.Length);
			hmac.doFinal(resBuf, 0);

			if (!areEqual(resBuf, Hex.decode(digests[vector])))
			{
				fail("Reset with vector " + vector + " failed");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new MD5HMacTest());
		}
	}

}