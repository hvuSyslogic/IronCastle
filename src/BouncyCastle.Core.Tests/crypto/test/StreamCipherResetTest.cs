using System;

namespace org.bouncycastle.crypto.test
{

	using ChaChaEngine = org.bouncycastle.crypto.engines.ChaChaEngine;
	using Grain128Engine = org.bouncycastle.crypto.engines.Grain128Engine;
	using Grainv1Engine = org.bouncycastle.crypto.engines.Grainv1Engine;
	using HC128Engine = org.bouncycastle.crypto.engines.HC128Engine;
	using HC256Engine = org.bouncycastle.crypto.engines.HC256Engine;
	using ISAACEngine = org.bouncycastle.crypto.engines.ISAACEngine;
	using RC4Engine = org.bouncycastle.crypto.engines.RC4Engine;
	using Salsa20Engine = org.bouncycastle.crypto.engines.Salsa20Engine;
	using XSalsa20Engine = org.bouncycastle.crypto.engines.XSalsa20Engine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Test whether block ciphers implement reset contract on init, encrypt/decrypt and reset.
	/// </summary>
	public class StreamCipherResetTest : SimpleTest
	{
		public override string getName()
		{
			return "Stream Cipher Reset";
		}

		public override void performTest()
		{
			testReset(new Salsa20Engine(), new Salsa20Engine(), new ParametersWithIV(new KeyParameter(random(32)), random(8)));
			testReset(new Salsa20Engine(), new Salsa20Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(8)));
			testReset(new XSalsa20Engine(), new XSalsa20Engine(), new ParametersWithIV(new KeyParameter(random(32)), random(24)));
			testReset(new ChaChaEngine(), new ChaChaEngine(), new ParametersWithIV(new KeyParameter(random(32)), random(8)));
			testReset(new ChaChaEngine(), new ChaChaEngine(), new ParametersWithIV(new KeyParameter(random(16)), random(8)));
			testReset(new RC4Engine(), new RC4Engine(), new KeyParameter(random(16)));
			testReset(new ISAACEngine(), new ISAACEngine(), new KeyParameter(random(16)));
			testReset(new HC128Engine(), new HC128Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(16)));
			testReset(new HC256Engine(), new HC256Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(16)));
			testReset(new Grainv1Engine(), new Grainv1Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(8)));
			testReset(new Grain128Engine(), new Grain128Engine(), new ParametersWithIV(new KeyParameter(random(16)), random(12)));
		}

		private static readonly SecureRandom RAND = new SecureRandom();

		private byte[] random(int size)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] data = new byte[size];
			byte[] data = new byte[size];
			RAND.nextBytes(data);
			return data;
		}

		private void testReset(StreamCipher cipher1, StreamCipher cipher2, CipherParameters @params)
		{
			cipher1.init(true, @params);

			byte[] plaintext = new byte[1023];
			byte[] ciphertext = new byte[plaintext.Length];

			// Establish baseline answer
			cipher1.processBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

			// Test encryption resets
			checkReset(cipher1, @params, true, plaintext, ciphertext);

			// Test decryption resets with fresh instance
			cipher2.init(false, @params);
			checkReset(cipher2, @params, false, ciphertext, plaintext);
		}

		private void checkReset(StreamCipher cipher, CipherParameters @params, bool encrypt, byte[] pretext, byte[] posttext)
		{
			// Do initial run
			byte[] output = new byte[posttext.Length];
			cipher.processBytes(pretext, 0, pretext.Length, output, 0);

			// Check encrypt resets cipher
			cipher.init(encrypt, @params);

			try
			{
				cipher.processBytes(pretext, 0, pretext.Length, output, 0);
			}
			catch (Exception e)
			{
				fail(cipher.getAlgorithmName() + " init did not reset: " + e.Message);
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(cipher.getAlgorithmName() + " init did not reset.", StringHelper.NewString(Hex.encode(posttext)), StringHelper.NewString(Hex.encode(output)));
			}

			// Check reset resets data
			cipher.reset();

			try
			{
				cipher.processBytes(pretext, 0, pretext.Length, output, 0);
			}
			catch (Exception e)
			{
				fail(cipher.getAlgorithmName() + " reset did not reset: " + e.Message);
			}
			if (!Arrays.areEqual(output, posttext))
			{
				fail(cipher.getAlgorithmName() + " reset did not reset.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new StreamCipherResetTest());
		}

	}

}