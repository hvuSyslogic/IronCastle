using System;

namespace org.bouncycastle.crypto.test
{

	using GeneralHashCommitter = org.bouncycastle.crypto.commitments.GeneralHashCommitter;
	using HashCommitter = org.bouncycastle.crypto.commitments.HashCommitter;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class HashCommitmentTest : SimpleTest
	{
		public override string getName()
		{
			return "HashCommitmentTest";
		}

		public virtual void performBasicTest()
		{
			byte[] data = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");

			Committer committer = new HashCommitter(new SHA256Digest(), new SecureRandom());

			Commitment c = committer.commit(data);

			committer = new HashCommitter(new SHA256Digest(), new SecureRandom());

			if (!committer.isRevealed(c, data))
			{
				fail("commitment failed to validate");
			}

			committer = new HashCommitter(new SHA1Digest(), new SecureRandom());

			if (committer.isRevealed(c, data))
			{
				fail("commitment validated!!");
			}

			try
			{
				committer.isRevealed(c, new byte[data.Length + 1]);
			}
			catch (Exception e)
			{
				if (!e.Message.Equals("Message and witness secret lengths do not match."))
				{
					fail("exception thrown but wrong message");
				}
			}

			// SHA1 has a block size of 512 bits, try a message that's too big

			try
			{
				c = committer.commit(new byte[33]);
			}
			catch (DataLengthException e)
			{
				if (!e.Message.Equals("Message to be committed to too large for digest."))
				{
					fail("exception thrown but wrong message");
				}
			}
		}

		public virtual void performGeneralTest()
		{
			byte[] data = Hex.decode("4e6f77206973207468652074696d6520666f7220616c6c20");

			Committer committer = new GeneralHashCommitter(new SHA256Digest(), new SecureRandom());

			Commitment c = committer.commit(data);

			committer = new GeneralHashCommitter(new SHA256Digest(), new SecureRandom());

			if (!committer.isRevealed(c, data))
			{
				fail("general commitment failed to validate");
			}

			committer = new GeneralHashCommitter(new SHA1Digest(), new SecureRandom());

			if (committer.isRevealed(c, data))
			{
				fail("general commitment validated!!");
			}

			c = committer.commit(data);

			// try and fool it.
			byte[] s = c.getSecret();
			byte[] newS = Arrays.copyOfRange(s, 0, s.Length - 1);
			byte[] newData = new byte[data.Length + 1];

			newData[0] = s[s.Length - 1];
			JavaSystem.arraycopy(data, 0, newData, 1, data.Length);

			c = new Commitment(newS, c.getCommitment());

			if (committer.isRevealed(c, newData))
			{
				fail("general commitment validated!!");
			}

			try
			{
				committer.isRevealed(c, new byte[data.Length + 1]);
			}
			catch (Exception e)
			{
				if (!e.Message.Equals("Message and witness secret lengths do not match."))
				{
					fail("exception thrown but wrong message");
				}
			}

			// SHA1 has a block size of 512 bits, try a message that's too big

			try
			{
				c = committer.commit(new byte[33]);
			}
			catch (DataLengthException e)
			{
				if (!e.Message.Equals("Message to be committed to too large for digest."))
				{
					fail("exception thrown but wrong message");
				}
			}
		}

		public override void performTest()
		{
			performBasicTest();
			performGeneralTest();
		}

		public static void Main(string[] args)
		{
			runTest(new HashCommitmentTest());
		}
	}

}