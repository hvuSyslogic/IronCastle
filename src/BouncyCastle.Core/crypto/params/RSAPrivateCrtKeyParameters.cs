using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class RSAPrivateCrtKeyParameters : RSAKeyParameters
	{
		private BigInteger e;
		private BigInteger p;
		private BigInteger q;
		private BigInteger dP;
		private BigInteger dQ;
		private BigInteger qInv;

		/// 
		public RSAPrivateCrtKeyParameters(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv) : base(true, modulus, privateExponent)
		{

			this.e = publicExponent;
			this.p = p;
			this.q = q;
			this.dP = dP;
			this.dQ = dQ;
			this.qInv = qInv;
		}

		public virtual BigInteger getPublicExponent()
		{
			return e;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		public virtual BigInteger getDP()
		{
			return dP;
		}

		public virtual BigInteger getDQ()
		{
			return dQ;
		}

		public virtual BigInteger getQInv()
		{
			return qInv;
		}
	}

}