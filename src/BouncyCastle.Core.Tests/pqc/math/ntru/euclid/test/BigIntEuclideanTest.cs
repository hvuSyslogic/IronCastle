namespace org.bouncycastle.pqc.math.ntru.euclid.test
{

	using TestCase = junit.framework.TestCase;

	public class BigIntEuclideanTest : TestCase
	{
		public virtual void testCalculate()
		{
			BigIntEuclidean r = BigIntEuclidean.calculate(BigInteger.valueOf(120), BigInteger.valueOf(23));
			assertEquals(BigInteger.valueOf(-9), r.x);
			assertEquals(BigInteger.valueOf(47), r.y);
			assertEquals(BigInteger.valueOf(1), r.gcd);

			r = BigIntEuclidean.calculate(BigInteger.valueOf(126), BigInteger.valueOf(231));
			assertEquals(BigInteger.valueOf(2), r.x);
			assertEquals(BigInteger.valueOf(-1), r.y);
			assertEquals(BigInteger.valueOf(21), r.gcd);
		}
	}
}