namespace org.bouncycastle.pqc.math.ntru.util.test
{

	using TestCase = junit.framework.TestCase;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using PolynomialGenerator = org.bouncycastle.pqc.math.ntru.polynomial.test.PolynomialGenerator;
	using Arrays = org.bouncycastle.util.Arrays;

	public class ArrayEncoderTest : TestCase
	{
		public virtual void testEncodeDecodeModQ()
		{
			int[] coeffs = PolynomialGenerator.generateRandom(1000, 2048).coeffs;
			byte[] data = ArrayEncoder.encodeModQ(coeffs, 2048);
			int[] coeffs2 = ArrayEncoder.decodeModQ(data, 1000, 2048);
			assertTrue(Arrays.areEqual(coeffs, coeffs2));
		}

		public virtual void testEncodeDecodeMod3Sves()
		{
			Random rng = new Random();
			byte[] data = new byte[180];
			rng.nextBytes(data);
			int[] coeffs = ArrayEncoder.decodeMod3Sves(data, 960);
			byte[] data2 = ArrayEncoder.encodeMod3Sves(coeffs);
			assertTrue(Arrays.areEqual(data, data2));
		}

		public virtual void testEncodeDecodeMod3Tight()
		{
			SecureRandom random = new SecureRandom();

			int[] coeffs = DenseTernaryPolynomial.generateRandom(1000, random).coeffs;
			byte[] data = ArrayEncoder.encodeMod3Tight(coeffs);
			int[] coeffs2 = ArrayEncoder.decodeMod3Tight(data, 1000);
			assertTrue(Arrays.areEqual(coeffs, coeffs2));
		}
	}
}