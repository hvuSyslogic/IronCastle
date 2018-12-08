using System;

namespace org.bouncycastle.crypto.test
{
	using RIPEMD128Digest = org.bouncycastle.crypto.digests.RIPEMD128Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// RIPEMD128 HMac Test, test vectors from RFC 2286
	/// </summary>
	public class RIPEMD128HMacTest : Test
	{
		internal static readonly string[] keys = new string[] {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

		internal static readonly string[] digests = new string[] {"fbf61f9492aa4bbf81c172e84e0734db", "875f828862b6b334b427c55f9f7ff09b", "09f0b2846d2f543da363cbec8d62a38d", "bdbbd7cf03e44b5aa60af815be4d2294", "e79808f24b25fd031c155f0d551d9a3a", "dc732928de98104a1f59d373c150acbb", "5c6bec96793e16d40690c237635f30c5"};

		internal static readonly string[] messages = new string[] {"Hi There", "what do ya want for nothing?", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "Test With Truncation", "Test Using Larger Than Block-Size Key - Hash Key First", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"};

		public virtual string getName()
		{
			return "RIPEMD128HMac";
		}

		public virtual TestResult perform()
		{
			HMac hmac = new HMac(new RIPEMD128Digest());
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
					return new SimpleTestResult(false, getName() + ": Vector " + i + " failed");
				}
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public static void Main(string[] args)
		{
			RIPEMD128HMacTest test = new RIPEMD128HMacTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}