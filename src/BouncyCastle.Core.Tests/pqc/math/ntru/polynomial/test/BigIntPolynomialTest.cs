namespace org.bouncycastle.pqc.math.ntru.polynomial.test
{

	using TestCase = junit.framework.TestCase;

	public class BigIntPolynomialTest : TestCase
	{
		public virtual void testMult()
		{
			BigIntPolynomial a = new BigIntPolynomial(new IntegerPolynomial(new int[]{4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5}));
			BigIntPolynomial b = new BigIntPolynomial(new IntegerPolynomial(new int[]{-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1}));
			BigIntPolynomial c = a.mult(b);
			BigInteger[] expectedCoeffs = (new BigIntPolynomial(new IntegerPolynomial(new int[]{2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34}))).getCoeffs();
			BigInteger[] cCoeffs = c.getCoeffs();

			assertEquals(expectedCoeffs.Length, cCoeffs.Length);
			for (int i = 0; i != cCoeffs.Length; i++)
			{
				assertEquals(expectedCoeffs[i], cCoeffs[i]);
			}
		}
	}
}