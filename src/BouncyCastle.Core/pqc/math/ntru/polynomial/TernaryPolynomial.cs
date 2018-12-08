namespace org.bouncycastle.pqc.math.ntru.polynomial
{
	/// <summary>
	/// A polynomial whose coefficients are all equal to -1, 0, or 1
	/// </summary>
	public interface TernaryPolynomial : Polynomial
	{

		/// <summary>
		/// Multiplies the polynomial by an <code>IntegerPolynomial</code>, taking the indices mod N
		/// </summary>
		IntegerPolynomial mult(IntegerPolynomial poly2);

		int[] getOnes();

		int[] getNegOnes();

		/// <summary>
		/// Returns the maximum number of coefficients the polynomial can have
		/// </summary>
		int size();

		void clear();
	}

}