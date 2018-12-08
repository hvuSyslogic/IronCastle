using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class DSAParameters : CipherParameters
	{
		private BigInteger g;
		private BigInteger q;
		private BigInteger p;
		private DSAValidationParameters validation;

		public DSAParameters(BigInteger p, BigInteger q, BigInteger g)
		{
			this.g = g;
			this.p = p;
			this.q = q;
		}

		public DSAParameters(BigInteger p, BigInteger q, BigInteger g, DSAValidationParameters @params)
		{
			this.g = g;
			this.p = p;
			this.q = q;
			this.validation = @params;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		public virtual BigInteger getG()
		{
			return g;
		}

		public virtual DSAValidationParameters getValidationParameters()
		{
			return validation;
		}

		public override bool Equals(object obj)
		{
			if (!(obj is DSAParameters))
			{
				return false;
			}

			DSAParameters pm = (DSAParameters)obj;

			return (pm.getP().Equals(p) && pm.getQ().Equals(q) && pm.getG().Equals(g));
		}

		public override int GetHashCode()
		{
			return getP().GetHashCode() ^ getQ().GetHashCode() ^ getG().GetHashCode();
		}
	}

}