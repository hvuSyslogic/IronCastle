namespace org.bouncycastle.crypto.test
{
	using EncodableDigest = org.bouncycastle.crypto.digests.EncodableDigest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Memoable = org.bouncycastle.util.Memoable;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public abstract class DigestTest : SimpleTest
	{
		private Digest digest;
		private string[] input;
		private string[] results;

		public DigestTest(Digest digest, string[] input, string[] results)
		{
			this.digest = digest;
			this.input = input;
			this.results = results;
		}

		public override string getName()
		{
			return digest.getAlgorithmName();
		}

		public override void performTest()
		{
			byte[] resBuf = new byte[digest.getDigestSize()];

			for (int i = 0; i < input.Length - 1; i++)
			{
				byte[] m = toByteArray(input[i]);

				vectorTest(digest, i, resBuf, m, Hex.decode(results[i]));
			}

			offsetTest(digest, 0, toByteArray(input[0]), Hex.decode(results[0]));

			byte[] lastV = toByteArray(input[input.Length - 1]);
			byte[] lastDigest = Hex.decode(results[input.Length - 1]);

			vectorTest(digest, input.Length - 1, resBuf, lastV, Hex.decode(results[input.Length - 1]));

			testClone(resBuf, lastV, lastDigest);
			testMemo(resBuf, lastV, lastDigest);
			if (digest is EncodableDigest)
			{
				testEncodedState(resBuf, lastV, lastDigest);
			}
		}

		private void testEncodedState(byte[] resBuf, byte[] input, byte[] expected)
		{
			// test state encoding;
			digest.update(input, 0, input.Length / 2);

			// copy the Digest
			Digest copy1 = cloneDigest(((EncodableDigest)digest).getEncodedState());
			Digest copy2 = cloneDigest(((EncodableDigest)copy1).getEncodedState());

			digest.update(input, input.Length / 2, input.Length - input.Length / 2);

			digest.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing state vector test", expected, StringHelper.NewString(Hex.encode(resBuf)));
			}

			copy1.update(input, input.Length / 2, input.Length - input.Length / 2);
			copy1.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing state copy1 vector test", expected, StringHelper.NewString(Hex.encode(resBuf)));
			}

			copy2.update(input, input.Length / 2, input.Length - input.Length / 2);
			copy2.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing state copy2 vector test", expected, StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		private void testMemo(byte[] resBuf, byte[] input, byte[] expected)
		{
			Memoable m = (Memoable)digest;

			digest.update(input, 0, input.Length / 2);

			// copy the Digest
			Memoable copy1 = m.copy();
			Memoable copy2 = copy1.copy();

			digest.update(input, input.Length / 2, input.Length - input.Length / 2);
			digest.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing memo vector test", results[results.Length - 1], StringHelper.NewString(Hex.encode(resBuf)));
			}

			m.reset(copy1);

			digest.update(input, input.Length / 2, input.Length - input.Length / 2);
			digest.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing memo reset vector test", results[results.Length - 1], StringHelper.NewString(Hex.encode(resBuf)));
			}

			Digest md = (Digest)copy2;

			md.update(input, input.Length / 2, input.Length - input.Length / 2);
			md.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing memo copy vector test", results[results.Length - 1], StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		private void testClone(byte[] resBuf, byte[] input, byte[] expected)
		{
			digest.update(input, 0, input.Length / 2);

			// clone the Digest
			Digest d = cloneDigest(digest);

			digest.update(input, input.Length / 2, input.Length - input.Length / 2);
			digest.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing clone vector test", results[results.Length - 1], StringHelper.NewString(Hex.encode(resBuf)));
			}

			d.update(input, input.Length / 2, input.Length - input.Length / 2);
			d.doFinal(resBuf, 0);

			if (!areEqual(expected, resBuf))
			{
				fail("failing second clone vector test", results[results.Length - 1], StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		public virtual byte[] toByteArray(string input)
		{
			byte[] bytes = new byte[input.Length];

			for (int i = 0; i != bytes.Length; i++)
			{
				bytes[i] = (byte)input[i];
			}

			return bytes;
		}

		private void vectorTest(Digest digest, int count, byte[] resBuf, byte[] input, byte[] expected)
		{
			digest.update(input, 0, input.Length);
			digest.doFinal(resBuf, 0);

			if (!areEqual(resBuf, expected))
			{
				fail("Vector " + count + " failed got " + StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		private void offsetTest(Digest digest, int count, byte[] input, byte[] expected)
		{
			byte[] resBuf = new byte[expected.Length + 11];

			digest.update(input, 0, input.Length);
			digest.doFinal(resBuf, 11);

			if (!areEqual(Arrays.copyOfRange(resBuf, 11, resBuf.Length), expected))
			{
				fail("Offset " + count + " failed got " + StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		public abstract Digest cloneDigest(Digest digest);

		public virtual Digest cloneDigest(byte[] encodedState)
		{
			throw new IllegalStateException("Unsupported");
		}

		//
		// optional tests
		//
		public virtual void millionATest(string expected)
		{
			byte[] resBuf = new byte[digest.getDigestSize()];

			for (int i = 0; i < 1000000; i++)
			{
				digest.update((byte)'a');
			}

			digest.doFinal(resBuf, 0);

			if (!areEqual(resBuf, Hex.decode(expected)))
			{
				fail("Million a's failed", expected, StringHelper.NewString(Hex.encode(resBuf)));
			}
		}

		public virtual void sixtyFourKTest(string expected)
		{
			byte[] resBuf = new byte[digest.getDigestSize()];

			for (int i = 0; i < 65536; i++)
			{
				digest.update(unchecked((byte)(i & 0xff)));
			}

			digest.doFinal(resBuf, 0);

			if (!areEqual(resBuf, Hex.decode(expected)))
			{
				fail("64k test failed", expected, StringHelper.NewString(Hex.encode(resBuf)));
			}
		}
	}

}