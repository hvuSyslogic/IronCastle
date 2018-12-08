using System;

namespace org.bouncycastle.crypto.test
{
	using NonMemoableDigest = org.bouncycastle.crypto.digests.NonMemoableDigest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// SHA1 HMac Test, test vectors from RFC 2202
	/// </summary>
	public class NonMemoableDigestTest : Test
	{
		internal static readonly string[] keys = new string[] {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

		internal static readonly string[] digests = new string[] {"b617318655057264e28bc0b6fb378c8ef146be00", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", "125d7342b9ac11cd91a39af48aa17b4f63f175d3", "4c9007f4026250c6bc8414f9bf50c86c2d7235da", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", "aa4ae5e15272d00e95705637ce8a3b55ed402112", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", "aa4ae5e15272d00e95705637ce8a3b55ed402112", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"};

		internal static readonly string[] messages = new string[] {"Hi There", "what do ya want for nothing?", "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "Test With Truncation", "Test Using Larger Than Block-Size Key - Hash Key First", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"};

		public virtual string getName()
		{
			return "NonMemoableDigest";
		}

		public virtual TestResult perform()
		{
			HMac hmac = new HMac(new NonMemoableDigest(new SHA1Digest()));
			byte[] resBuf = new byte[hmac.getMacSize()];

			for (int i = 0; i < messages.Length; i++)
			{
				byte[] m = Strings.toByteArray(messages[i]);
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

			//
			// test reset
			//
			int vector = 0; // vector used for test
			byte[] m = Strings.toByteArray(messages[vector]);
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
				return new SimpleTestResult(false, getName() + ": Reset with vector " + vector + " failed");
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public static void Main(string[] args)
		{
			NonMemoableDigestTest test = new NonMemoableDigestTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}