namespace org.bouncycastle.pqc.math.ntru.polynomial.test
{

	using TestCase = junit.framework.TestCase;

	public class BigDecimalPolynomialTest : TestCase
	{
		public virtual void testMult()
		{
			BigDecimalPolynomial a = new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[]{4, -1, 9, 2, 1, -5, 12, -7, 0, -9, 5})));
			BigDecimalPolynomial b = new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[]{-6, 0, 0, 13, 3, -2, -4, 10, 11, 2, -1})));
			BigDecimalPolynomial c = a.mult(b);
			BigDecimal[] expectedCoeffs = (new BigDecimalPolynomial(new BigIntPolynomial(new IntegerPolynomial(new int[]{2, -189, 77, 124, -29, 0, -75, 124, -49, 267, 34})))).getCoeffs();

			BigDecimal[] cCoeffs = c.getCoeffs();

			assertEquals(expectedCoeffs.Length, cCoeffs.Length);
			for (int i = 0; i != cCoeffs.Length; i++)
			{
				assertEquals(expectedCoeffs[i], cCoeffs[i]);
			}

			// multiply a polynomial by its inverse modulo 2048 and check that the result is 1
			SecureRandom random = new SecureRandom();
			IntegerPolynomial d, dInv;
			do
			{
				d = DenseTernaryPolynomial.generateRandom(1001, 333, 334, random);
				dInv = d.invertFq(2048);
			} while (dInv == null);

			d.mod(2048);
			BigDecimalPolynomial e = new BigDecimalPolynomial(new BigIntPolynomial(d));
			BigIntPolynomial f = new BigIntPolynomial(dInv);
			IntegerPolynomial g = new IntegerPolynomial(e.mult(f).round());
			g.modPositive(2048);
			assertTrue(g.equalsOne());
		}
	}
}