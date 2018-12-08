namespace org.bouncycastle.crypto.prng
{

	/// <summary>
	/// Random generation based on the digest with counter. Calling addSeedMaterial will
	/// always increase the entropy of the hash.
	/// <para>
	/// Internal access to the digest is synchronized so a single one of these can be shared.
	/// </para>
	/// </summary>
	public class DigestRandomGenerator : RandomGenerator
	{
		private static long CYCLE_COUNT = 10;

		private long stateCounter;
		private long seedCounter;
		private Digest digest;
		private byte[] state;
		private byte[] seed;

		// public constructors
		public DigestRandomGenerator(Digest digest)
		{
			this.digest = digest;

			this.seed = new byte[digest.getDigestSize()];
			this.seedCounter = 1;

			this.state = new byte[digest.getDigestSize()];
			this.stateCounter = 1;
		}

		public virtual void addSeedMaterial(byte[] inSeed)
		{
			lock (this)
			{
				digestUpdate(inSeed);
				digestUpdate(seed);
				digestDoFinal(seed);
			}
		}

		public virtual void addSeedMaterial(long rSeed)
		{
			lock (this)
			{
				digestAddCounter(rSeed);
				digestUpdate(seed);

				digestDoFinal(seed);
			}
		}

		public virtual void nextBytes(byte[] bytes)
		{
			nextBytes(bytes, 0, bytes.Length);
		}

		public virtual void nextBytes(byte[] bytes, int start, int len)
		{
			lock (this)
			{
				int stateOff = 0;

				generateState();

				int end = start + len;
				for (int i = start; i != end; i++)
				{
					if (stateOff == state.Length)
					{
						generateState();
						stateOff = 0;
					}
					bytes[i] = state[stateOff++];
				}
			}
		}

		private void cycleSeed()
		{
			digestUpdate(seed);
			digestAddCounter(seedCounter++);

			digestDoFinal(seed);
		}

		private void generateState()
		{
			digestAddCounter(stateCounter++);
			digestUpdate(state);
			digestUpdate(seed);

			digestDoFinal(state);

			if ((stateCounter % CYCLE_COUNT) == 0)
			{
				cycleSeed();
			}
		}

		private void digestAddCounter(long seed)
		{
			for (int i = 0; i != 8; i++)
			{
				digest.update((byte)seed);
				seed = (long)((ulong)seed >> 8);
			}
		}

		private void digestUpdate(byte[] inSeed)
		{
			digest.update(inSeed, 0, inSeed.Length);
		}

		private void digestDoFinal(byte[] result)
		{
			digest.doFinal(result, 0);
		}
	}

}