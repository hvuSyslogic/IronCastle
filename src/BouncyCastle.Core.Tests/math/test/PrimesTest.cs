namespace org.bouncycastle.math.test
{

	using Test = junit.framework.Test;
	using TestCase = junit.framework.TestCase;
	using TestSuite = junit.framework.TestSuite;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using MROutput = org.bouncycastle.math.Primes.MROutput;
	using STOutput = org.bouncycastle.math.Primes.STOutput;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class PrimesTest : TestCase
	{
		private const int ITERATIONS = 10;
		private const int PRIME_BITS = 256;
		private const int PRIME_CERTAINTY = 100;

		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		private static readonly SecureRandom R = new SecureRandom();

		public virtual void testHasAnySmallFactors()
		{
			for (int iterations = 0; iterations < ITERATIONS; ++iterations)
			{
				BigInteger prime = randomPrime();
				assertFalse(Primes.hasAnySmallFactors(prime));

				// NOTE: Loop through ALL small values to be sure no small primes are missing
				for (int smallFactor = 2; smallFactor <= Primes.SMALL_FACTOR_LIMIT; ++smallFactor)
				{
					BigInteger nonPrimeWithSmallFactor = BigInteger.valueOf(smallFactor).multiply(prime);
					assertTrue(Primes.hasAnySmallFactors(nonPrimeWithSmallFactor));
				}
			}
		}

		public virtual void testEnhancedMRProbablePrime()
		{
			int mrIterations = (PRIME_CERTAINTY + 1) / 2;
			for (int iterations = 0; iterations < ITERATIONS; ++iterations)
			{
				BigInteger prime = randomPrime();
				Primes.MROutput mr = Primes.enhancedMRProbablePrimeTest(prime, R, mrIterations);
				assertFalse(mr.isProvablyComposite());
				assertFalse(mr.isNotPrimePower());
				assertNull(mr.getFactor());

				BigInteger primePower = prime;
				for (int i = 0; i <= (iterations % 8); ++i)
				{
					primePower = primePower.multiply(prime);
				}

				Primes.MROutput mr2 = Primes.enhancedMRProbablePrimeTest(primePower, R, mrIterations);
				assertTrue(mr2.isProvablyComposite());
				assertFalse(mr2.isNotPrimePower());
				assertEquals(mr2.getFactor(), prime);

				BigInteger nonPrimePower = randomPrime().multiply(prime);
				Primes.MROutput mr3 = Primes.enhancedMRProbablePrimeTest(nonPrimePower, R, mrIterations);
				assertTrue(mr3.isProvablyComposite());
				assertTrue(mr3.isNotPrimePower());
				assertNull(mr.getFactor());
			}
		}

		public virtual void testMRProbablePrime()
		{
			int mrIterations = (PRIME_CERTAINTY + 1) / 2;
			for (int iterations = 0; iterations < ITERATIONS; ++iterations)
			{
				BigInteger prime = randomPrime();
				assertTrue(Primes.isMRProbablePrime(prime, R, mrIterations));

				BigInteger nonPrime = randomPrime().multiply(prime);
				assertFalse(Primes.isMRProbablePrime(nonPrime, R, mrIterations));
			}
		}

		public virtual void testMRProbablePrimeToBase()
		{
			int mrIterations = (PRIME_CERTAINTY + 1) / 2;
			for (int iterations = 0; iterations < ITERATIONS; ++iterations)
			{
				BigInteger prime = randomPrime();
				assertTrue(referenceIsMRProbablePrime(prime, mrIterations));

				BigInteger nonPrime = randomPrime().multiply(prime);
				assertFalse(referenceIsMRProbablePrime(nonPrime, mrIterations));
			}
		}

		public virtual void testSTRandomPrime()
		{
			Digest[] digests = new Digest[]
			{
				new SHA1Digest(),
				new SHA256Digest()
			};
			for (int digestIndex = 0; digestIndex < digests.Length; ++digestIndex)
			{
				int coincidenceCount = 0;

				Digest digest = digests[digestIndex];
				for (int iterations = 0; iterations < ITERATIONS; ++iterations)
				{
					try
					{
						byte[] inputSeed = new byte[16];
						R.nextBytes(inputSeed);

						Primes.STOutput st = Primes.generateSTRandomPrime(digest, PRIME_BITS, inputSeed);
						assertTrue(isPrime(st.getPrime()));

						Primes.STOutput st2 = Primes.generateSTRandomPrime(digest, PRIME_BITS, inputSeed);
						assertEquals(st.getPrime(), st2.getPrime());
						assertEquals(st.getPrimeGenCounter(), st2.getPrimeGenCounter());
						assertTrue(Arrays.areEqual(st.getPrimeSeed(), st2.getPrimeSeed()));

						for (int i = 0; i < inputSeed.Length; ++i)
						{
							inputSeed[i] ^= unchecked((byte)0xFF);
						}

						Primes.STOutput st3 = Primes.generateSTRandomPrime(digest, PRIME_BITS, inputSeed);
						assertTrue(!st.getPrime().Equals(st3.getPrime()));
						assertFalse(Arrays.areEqual(st.getPrimeSeed(), st3.getPrimeSeed()));

						if (st.getPrimeGenCounter() == st3.getPrimeGenCounter())
						{
							++coincidenceCount;
						}
					}
					catch (IllegalStateException e)
					{
						if (e.getMessage().StartsWith("Too many iterations"))
						{
							--iterations;
							continue;
						}

						throw e;
					}
				}

				assertTrue(coincidenceCount * coincidenceCount < ITERATIONS);
			}
		}

		public static Test suite()
		{
			return new TestSuite(typeof(PrimesTest));
		}

		private static bool referenceIsMRProbablePrime(BigInteger x, int numBases)
		{
			BigInteger xSubTwo = x.subtract(TWO);

			for (int i = 0; i < numBases; ++i)
			{
				BigInteger b = BigIntegers.createRandomInRange(TWO, xSubTwo, R);
				if (!Primes.isMRProbablePrimeToBase(x, b))
				{
					return false;
				}
			}

			return true;
		}

		private static bool isPrime(BigInteger x)
		{
			return x.isProbablePrime(PRIME_CERTAINTY);
		}

		private static BigInteger randomPrime()
		{
			return BigIntegers.createRandomPrime(PRIME_BITS, PRIME_CERTAINTY, R);
		}
	}

}