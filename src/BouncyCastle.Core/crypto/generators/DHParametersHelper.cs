﻿using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.generators
{

	using WNafUtil = org.bouncycastle.math.ec.WNafUtil;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class DHParametersHelper
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		/*
		 * Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
		 * 
		 * (see: Handbook of Applied Cryptography 4.86)
		 */
		internal static BigInteger[] generateSafePrimes(int size, int certainty, SecureRandom random)
		{
			BigInteger p, q;
			int qLength = size - 1;
			int minWeight = (int)((uint)size >> 2);

			for (;;)
			{
				q = BigIntegers.createRandomPrime(qLength, 2, random);

				// p <- 2q + 1
				p = q.shiftLeft(1).add(ONE);

				if (!p.isProbablePrime(certainty))
				{
					continue;
				}

				if (certainty > 2 && !q.isProbablePrime(certainty - 2))
				{
					continue;
				}

				/*
				 * Require a minimum weight of the NAF representation, since low-weight primes may be
				 * weak against a version of the number-field-sieve for the discrete-logarithm-problem.
				 * 
				 * See "The number field sieve for integers of low weight", Oliver Schirokauer.
				 */
				if (WNafUtil.getNafWeight(p) < minWeight)
				{
					continue;
				}

				break;
			}

			return new BigInteger[] {p, q};
		}

		/*
		 * Select a high order element of the multiplicative group Zp*
		 * 
		 * p and q must be s.t. p = 2*q + 1, where p and q are prime (see generateSafePrimes)
		 */
		internal static BigInteger selectGenerator(BigInteger p, BigInteger q, SecureRandom random)
		{
			BigInteger pMinusTwo = p.subtract(TWO);
			BigInteger g;

			/*
			 * (see: Handbook of Applied Cryptography 4.80)
			 */
	//        do
	//        {
	//            g = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
	//        }
	//        while (g.modPow(TWO, p).equals(ONE) || g.modPow(q, p).equals(ONE));


			/*
			 * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
			 */
			do
			{
				BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);

				g = h.modPow(TWO, p);
			} while (g.Equals(ONE));


			return g;
		}
	}

}