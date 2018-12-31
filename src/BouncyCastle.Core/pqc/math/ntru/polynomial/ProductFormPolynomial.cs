using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.math.ntru.polynomial
{

	
	/// <summary>
	/// A polynomial of the form <code>f1*f2+f3</code>, where
	/// <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
	/// </summary>
	public class ProductFormPolynomial : Polynomial
	{
		private SparseTernaryPolynomial f1, f2, f3;

		public ProductFormPolynomial(SparseTernaryPolynomial f1, SparseTernaryPolynomial f2, SparseTernaryPolynomial f3)
		{
			this.f1 = f1;
			this.f2 = f2;
			this.f3 = f3;
		}

		public static ProductFormPolynomial generateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, SecureRandom random)
		{
			SparseTernaryPolynomial f1 = SparseTernaryPolynomial.generateRandom(N, df1, df1, random);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.generateRandom(N, df2, df2, random);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, random);
			return new ProductFormPolynomial(f1, f2, f3);
		}

		public static ProductFormPolynomial fromBinary(byte[] data, int N, int df1, int df2, int df3Ones, int df3NegOnes)
		{
			return fromBinary(new ByteArrayInputStream(data), N, df1, df2, df3Ones, df3NegOnes);
		}

		public static ProductFormPolynomial fromBinary(InputStream @is, int N, int df1, int df2, int df3Ones, int df3NegOnes)
		{
			SparseTernaryPolynomial f1;

			f1 = SparseTernaryPolynomial.fromBinary(@is, N, df1, df1);
			SparseTernaryPolynomial f2 = SparseTernaryPolynomial.fromBinary(@is, N, df2, df2);
			SparseTernaryPolynomial f3 = SparseTernaryPolynomial.fromBinary(@is, N, df3Ones, df3NegOnes);
			return new ProductFormPolynomial(f1, f2, f3);
		}

		public virtual byte[] toBinary()
		{
			byte[] f1Bin = f1.toBinary();
			byte[] f2Bin = f2.toBinary();
			byte[] f3Bin = f3.toBinary();

			byte[] all = Arrays.copyOf(f1Bin, f1Bin.Length + f2Bin.Length + f3Bin.Length);
			JavaSystem.arraycopy(f2Bin, 0, all, f1Bin.Length, f2Bin.Length);
			JavaSystem.arraycopy(f3Bin, 0, all, f1Bin.Length + f2Bin.Length, f3Bin.Length);
			return all;
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial b)
		{
			IntegerPolynomial c = f1.mult(b);
			c = f2.mult(c);
			c.add(f3.mult(b));
			return c;
		}

		public virtual BigIntPolynomial mult(BigIntPolynomial b)
		{
			BigIntPolynomial c = f1.mult(b);
			c = f2.mult(c);
			c.add(f3.mult(b));
			return c;
		}

		public virtual IntegerPolynomial toIntegerPolynomial()
		{
			IntegerPolynomial i = f1.mult(f2.toIntegerPolynomial());
			i.add(f3.toIntegerPolynomial());
			return i;
		}

		public virtual IntegerPolynomial mult(IntegerPolynomial poly2, int modulus)
		{
			IntegerPolynomial c = mult(poly2);
			c.mod(modulus);
			return c;
		}

		public override int GetHashCode()
		{
			const int prime = 31;
			int result = 1;
			result = prime * result + ((f1 == null) ? 0 : f1.GetHashCode());
			result = prime * result + ((f2 == null) ? 0 : f2.GetHashCode());
			result = prime * result + ((f3 == null) ? 0 : f3.GetHashCode());
			return result;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (obj == null)
			{
				return false;
			}
			if (this.GetType() != obj.GetType())
			{
				return false;
			}
			ProductFormPolynomial other = (ProductFormPolynomial)obj;
			if (f1 == null)
			{
				if (other.f1 != null)
				{
					return false;
				}
			}
			else if (!f1.Equals(other.f1))
			{
				return false;
			}
			if (f2 == null)
			{
				if (other.f2 != null)
				{
					return false;
				}
			}
			else if (!f2.Equals(other.f2))
			{
				return false;
			}
			if (f3 == null)
			{
				if (other.f3 != null)
				{
					return false;
				}
			}
			else if (!f3.Equals(other.f3))
			{
				return false;
			}
			return true;
		}
	}

}