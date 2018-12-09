﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.field
{

	public abstract class FiniteFields
	{
		internal static readonly FiniteField GF_2 = new PrimeField(BigInteger.valueOf(2));
		internal static readonly FiniteField GF_3 = new PrimeField(BigInteger.valueOf(3));

		public static PolynomialExtensionField getBinaryExtensionField(int[] exponents)
		{
			if (exponents[0] != 0)
			{
				throw new IllegalArgumentException("Irreducible polynomials in GF(2) must have constant term");
			}
			for (int i = 1; i < exponents.Length; ++i)
			{
				if (exponents[i] <= exponents[i - 1])
				{
					throw new IllegalArgumentException("Polynomial exponents must be montonically increasing");
				}
			}

			return new GenericPolynomialExtensionField(GF_2, new GF2Polynomial(exponents));
		}

	//    public static PolynomialExtensionField getTernaryExtensionField(Term[] terms)
	//    {
	//        return new GenericPolynomialExtensionField(GF_3, new GF3Polynomial(terms));
	//    }

		public static FiniteField getPrimeField(BigInteger characteristic)
		{
			int bitLength = characteristic.bitLength();
			if (characteristic.signum() <= 0 || bitLength < 2)
			{
				throw new IllegalArgumentException("'characteristic' must be >= 2");
			}

			if (bitLength < 3)
			{
				switch (characteristic.intValue())
				{
				case 2:
					return GF_2;
				case 3:
					return GF_3;
				}
			}

			return new PrimeField(characteristic);
		}
	}

}