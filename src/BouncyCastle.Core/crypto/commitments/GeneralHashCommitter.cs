﻿using BouncyCastle.Core.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.commitments
{

	
	/// <summary>
	/// A basic hash-committer based on the one described in "Making Mix Nets Robust for Electronic Voting by Randomized Partial Checking",
	/// by Jakobsson, Juels, and Rivest (11th Usenix Security Symposium, 2002).
	/// <para>
	/// The algorithm used by this class differs from the one given in that it includes the length of the message in the hash calculation.
	/// </para>
	/// </summary>
	public class GeneralHashCommitter : Committer
	{
		private readonly Digest digest;
		private readonly int byteLength;
		private readonly SecureRandom random;

		/// <summary>
		/// Base Constructor. The maximum message length that can be committed to is half the length of the internal
		/// block size for the digest (ExtendedDigest.getBlockLength()).
		/// </summary>
		/// <param name="digest"> digest to use for creating commitments. </param>
		/// <param name="random"> source of randomness for generating secrets. </param>
		public GeneralHashCommitter(ExtendedDigest digest, SecureRandom random)
		{
			this.digest = digest;
			this.byteLength = digest.getByteLength();
			this.random = random;
		}

		/// <summary>
		/// Generate a commitment for the passed in message.
		/// </summary>
		/// <param name="message"> the message to be committed to, </param>
		/// <returns> a Commitment </returns>
		public virtual Commitment commit(byte[] message)
		{
			if (message.Length > byteLength / 2)
			{
				throw new DataLengthException("Message to be committed to too large for digest.");
			}

			byte[] w = new byte[byteLength - message.Length];

			random.nextBytes(w);

			return new Commitment(w, calculateCommitment(w, message));
		}

		/// <summary>
		/// Return true if the passed in commitment represents a commitment to the passed in message.
		/// </summary>
		/// <param name="commitment"> a commitment previously generated. </param>
		/// <param name="message"> the message that was expected to have been committed to. </param>
		/// <returns> true if commitment matches message, false otherwise. </returns>
		public virtual bool isRevealed(Commitment commitment, byte[] message)
		{
			if (message.Length + commitment.getSecret().Length != byteLength)
			{
				throw new DataLengthException("Message and witness secret lengths do not match.");
			}

			byte[] calcCommitment = calculateCommitment(commitment.getSecret(), message);

			return Arrays.constantTimeAreEqual(commitment.getCommitment(), calcCommitment);
		}

		private byte[] calculateCommitment(byte[] w, byte[] message)
		{
			byte[] commitment = new byte[digest.getDigestSize()];

			digest.update(w, 0, w.Length);
			digest.update(message, 0, message.Length);

			digest.update((byte)(((int)((uint)message.Length >> 8))));
			digest.update((byte)(message.Length));

			digest.doFinal(commitment, 0);

			return commitment;
		}
	}

}