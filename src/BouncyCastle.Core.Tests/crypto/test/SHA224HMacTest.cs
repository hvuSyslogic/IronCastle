using System;

namespace org.bouncycastle.crypto.test
{
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// SHA224 HMac Test
	/// </summary>
	public class SHA224HMacTest : Test
	{
		internal static readonly string[] keys = new string[] {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

		internal static readonly string[] digests = new string[] {"896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22", "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44", "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea", "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a", "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c", "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e", "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"};

		internal static readonly string[] messages = new string[] {"Hi There", "what do ya want for nothing?", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "Test With Truncation", "Test Using Larger Than Block-Size Key - Hash Key First", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."};

		public virtual string getName()
		{
			return "SHA224HMac";
		}

		public virtual TestResult perform()
		{
			HMac hmac = new HMac(new SHA224Digest());
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
			SHA224HMacTest test = new SHA224HMacTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}