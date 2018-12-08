namespace org.bouncycastle.pqc.math.ntru.polynomial.test
{

	public class PolynomialGenerator
	{
		/// <summary>
		/// Creates a random polynomial with <code>N</code> coefficients
		/// between <code>0</code> and <code>q-1</code>.
		/// </summary>
		/// <param name="N"> length of the polynomial </param>
		/// <param name="q"> coefficients will all be below this number </param>
		/// <returns> a random polynomial </returns>
		public static IntegerPolynomial generateRandom(int N, int q)
		{
			Random rng = new Random();
			int[] coeffs = new int[N];
			for (int i = 0; i < N; i++)
			{
				coeffs[i] = rng.nextInt(q);
			}
			return new IntegerPolynomial(coeffs);
		}
	}
}