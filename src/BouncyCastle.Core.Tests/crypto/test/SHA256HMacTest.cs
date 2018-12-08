using System;

namespace org.bouncycastle.crypto.test
{
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// SHA256 HMac Test
	/// </summary>
	public class SHA256HMacTest : Test
	{
		internal static readonly string[] keys = new string[] {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

		internal static readonly string[] digests = new string[] {"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"};

		internal static readonly string[] messages = new string[] {"Hi There", "what do ya want for nothing?", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "Test With Truncation", "Test Using Larger Than Block-Size Key - Hash Key First", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."};

		public virtual string getName()
		{
			return "SHA256HMac";
		}

		public virtual TestResult perform()
		{
			HMac hmac = new HMac(new SHA256Digest());
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

				if (!Arrays.areEqual(resBuf, Hex.decode(digests[i])))
				{
					return new SimpleTestResult(false, getName() + ": Vector " + i + " failed got -" + StringHelper.NewString(Hex.encode(resBuf)));
				}
			}

			//
			// test reset
			//
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

			if (!Arrays.areEqual(resBuf, Hex.decode(digests[vector])))
			{
				return new SimpleTestResult(false, getName() + "Reset with vector " + vector + " failed");
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public static void Main(string[] args)
		{
			SHA256HMacTest test = new SHA256HMacTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}