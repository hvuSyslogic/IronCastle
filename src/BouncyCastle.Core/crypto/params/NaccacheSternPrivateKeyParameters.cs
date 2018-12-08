using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Private key parameters for NaccacheStern cipher. For details on this cipher,
	/// please see
	/// 
	/// http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	/// </summary>
	public class NaccacheSternPrivateKeyParameters : NaccacheSternKeyParameters
	{
		private BigInteger phi_n;
		private Vector smallPrimes;

		/// <summary>
		/// Constructs a NaccacheSternPrivateKey
		/// </summary>
		/// <param name="g">
		///            the public enryption parameter g </param>
		/// <param name="n">
		///            the public modulus n = p*q </param>
		/// <param name="lowerSigmaBound">
		///            the public lower sigma bound up to which data can be encrypted </param>
		/// <param name="smallPrimes">
		///            the small primes, of which sigma is constructed in the right
		///            order </param>
		/// <param name="phi_n">
		///            the private modulus phi(n) = (p-1)(q-1) </param>
		public NaccacheSternPrivateKeyParameters(BigInteger g, BigInteger n, int lowerSigmaBound, Vector smallPrimes, BigInteger phi_n) : base(true, g, n, lowerSigmaBound)
		{
			this.smallPrimes = smallPrimes;
			this.phi_n = phi_n;
		}

		public virtual BigInteger getPhi_n()
		{
			return phi_n;
		}

		public virtual Vector getSmallPrimes()
		{
			return smallPrimes;
		}
	}

}