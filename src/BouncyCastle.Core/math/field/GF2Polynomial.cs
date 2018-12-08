namespace org.bouncycastle.math.field
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class GF2Polynomial : Polynomial
	{
		protected internal readonly int[] exponents;

		public GF2Polynomial(int[] exponents)
		{
			this.exponents = Arrays.clone(exponents);
		}

		public virtual int getDegree()
		{
			return exponents[exponents.Length - 1];
		}

		public virtual int[] getExponentsPresent()
		{
			return Arrays.clone(exponents);
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (!(obj is GF2Polynomial))
			{
				return false;
			}
			GF2Polynomial other = (GF2Polynomial)obj;
			return Arrays.areEqual(exponents, other.exponents);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(exponents);
		}
	}

}