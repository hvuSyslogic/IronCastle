using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.math.ntru.polynomial
{

	/// <summary>
	/// Contains a resultant and a polynomial <code>rho</code> such that
	/// <code>res = rho*this + t*(x^n-1) for some integer t</code>.
	/// </summary>
	/// <seealso cref= IntegerPolynomial#resultant() </seealso>
	/// <seealso cref= IntegerPolynomial#resultant(int) </seealso>
	public class Resultant
	{
		/// <summary>
		/// A polynomial such that <code>res = rho*this + t*(x^n-1) for some integer t</code>
		/// </summary>
		public BigIntPolynomial rho;
		/// <summary>
		/// Resultant of a polynomial with <code>x^n-1</code>
		/// </summary>
		public BigInteger res;

		public Resultant(BigIntPolynomial rho, BigInteger res)
		{
			this.rho = rho;
			this.res = res;
		}
	}

}