using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	public class GOST3410Parameters : CipherParameters
	{
		private BigInteger p;
		private BigInteger q;
		private BigInteger a;
		private GOST3410ValidationParameters validation;

		public GOST3410Parameters(BigInteger p, BigInteger q, BigInteger a)
		{
			this.p = p;
			this.q = q;
			this.a = a;
		}

		public GOST3410Parameters(BigInteger p, BigInteger q, BigInteger a, GOST3410ValidationParameters @params)
		{
			this.a = a;
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

		public virtual BigInteger getA()
		{
			return a;
		}

		public virtual GOST3410ValidationParameters getValidationParameters()
		{
			return validation;
		}

		public override int GetHashCode()
		{
			return p.GetHashCode() ^ q.GetHashCode() ^ a.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			if (!(obj is GOST3410Parameters))
			{
				return false;
			}

			GOST3410Parameters pm = (GOST3410Parameters)obj;

			return (pm.getP().Equals(p) && pm.getQ().Equals(q) && pm.getA().Equals(a));
		}
	}

}