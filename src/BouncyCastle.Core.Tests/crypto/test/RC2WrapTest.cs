using System;

namespace org.bouncycastle.crypto.test
{

	using RC2WrapEngine = org.bouncycastle.crypto.engines.RC2WrapEngine;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	/// <summary>
	/// RC2 wrap tester
	/// </summary>
	public class RC2WrapTest : Test
	{
		public class RFCRandom : SecureRandom
		{
			private readonly RC2WrapTest outerInstance;

			public RFCRandom(RC2WrapTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual void nextBytes(byte[] nextBytes)
			{
				JavaSystem.arraycopy(Hex.decode("4845cce7fd1250"), 0, nextBytes, 0, nextBytes.Length);
			}
		}

		private TestResult wrapTest(int id, CipherParameters paramsWrap, CipherParameters paramsUnwrap, byte[] @in, byte[] @out)
		{
			Wrapper wrapper = new RC2WrapEngine();

			wrapper.init(true, paramsWrap);

			try
			{
				byte[] cText = wrapper.wrap(@in, 0, @in.Length);
				if (!Arrays.areEqual(cText, @out))
				{
					return new SimpleTestResult(false, getName() + ": failed wrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@out)) + " got " + StringHelper.NewString(Hex.encode(cText)));
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.ToString(), e);
			}

			wrapper.init(false, paramsUnwrap);

			try
			{
				byte[] pText = wrapper.unwrap(@out, 0, @out.Length);
				if (!Arrays.areEqual(pText, @in))
				{
					return new SimpleTestResult(false, getName() + ": failed unwrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@in)) + " got " + StringHelper.NewString(Hex.encode(pText)));
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": failed unwrap test exception " + e.ToString(), e);
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual TestResult perform()
		{
			byte[] kek1 = Hex.decode("fd04fd08060707fb0003fefffd02fe05");
			byte[] iv1 = Hex.decode("c7d90059b29e97f7");
			byte[] in1 = Hex.decode("b70a25fbc9d86a86050ce0d711ead4d9");
			byte[] out1 = Hex.decode("70e699fb5701f7833330fb71e87c85a420bdc99af05d22af5a0e48d35f3138986cbaafb4b28d4f35");
			// 
			// note the RFC 3217 test specifies a key to be used with an effective key size of
			// 40 bits which is why it is done here - in practice nothing less than 128 bits should be used.
			//
			CipherParameters paramWrap = new ParametersWithRandom(new ParametersWithIV(new RC2Parameters(kek1, 40), iv1), new RFCRandom(this));
			CipherParameters paramUnwrap = new RC2Parameters(kek1, 40);

			TestResult result = wrapTest(1, paramWrap, paramUnwrap, in1, out1);

			if (!result.isSuccessful())
			{
				return result;
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual string getName()
		{
			return "RC2Wrap";
		}

		public static void Main(string[] args)
		{
			RC2WrapTest test = new RC2WrapTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}