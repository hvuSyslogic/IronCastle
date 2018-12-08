using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec.endo
{

	public class GLVTypeBParameters
	{
		private static void checkVector(BigInteger[] v, string name)
		{
			if (v == null || v.Length != 2 || v[0] == null || v[1] == null)
			{
				throw new IllegalArgumentException("'" + name + "' must consist of exactly 2 (non-null) values");
			}
		}

		protected internal readonly BigInteger beta;
		protected internal readonly BigInteger lambda;
		protected internal readonly BigInteger v1A, v1B, v2A, v2B;
		protected internal readonly BigInteger g1, g2;
		protected internal readonly int bits;

		public GLVTypeBParameters(BigInteger beta, BigInteger lambda, BigInteger[] v1, BigInteger[] v2, BigInteger g1, BigInteger g2, int bits)
		{
			checkVector(v1, "v1");
			checkVector(v2, "v2");

			this.beta = beta;
			this.lambda = lambda;
			this.v1A = v1[0];
			this.v1B = v1[1];
			this.v2A = v2[0];
			this.v2B = v2[1];
			this.g1 = g1;
			this.g2 = g2;
			this.bits = bits;
		}

		public virtual BigInteger getBeta()
		{
			return beta;
		}

		public virtual BigInteger getLambda()
		{
			return lambda;
		}

		/// @deprecated Use <seealso cref="#getV1A()"/> and <seealso cref="#getV1B()"/> instead. 
		public virtual BigInteger[] getV1()
		{
			return new BigInteger[]{v1A, v1B};
		}

		public virtual BigInteger getV1A()
		{
			return v1A;
		}

		public virtual BigInteger getV1B()
		{
			return v1B;
		}

		/// @deprecated Use <seealso cref="#getV2A()"/> and <seealso cref="#getV2B()"/> instead. 
		public virtual BigInteger[] getV2()
		{
			return new BigInteger[]{v2A, v2B};
		}

		public virtual BigInteger getV2A()
		{
			return v2A;
		}

		public virtual BigInteger getV2B()
		{
			return v2B;
		}

		public virtual BigInteger getG1()
		{
			return g1;
		}

		public virtual BigInteger getG2()
		{
			return g2;
		}

		public virtual int getBits()
		{
			return bits;
		}
	}

}